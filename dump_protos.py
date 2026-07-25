#!/usr/bin/env python3
"""extract every google.protobuf FileDescriptorProto embedded in an il2cpp build

each descriptor is emitted as Convert.FromBase64String(string.Concat("chunk1", "chunk2", ...))
inside a *Reflection..cctor. the chunks are separate deduplicated non-contiguous string literals
so the descriptor is reassembled from the cctor code

- parse dump.cs for every *Reflection..cctor va (plus all method vas, so a function ends where the
  next one starts)
- a chunk load is `adrp xN,#page` then `ldr xN,[xN,#off]`. the slot page+off is a metadata-usage
  pointer, zero in the file and filled by an elf relocation at load time, so it resolves through
  the reloc table as addend to string-literal address to stringliteral.json value
- concat order is the string[] build order, chunks stored at `str xV,[arr,#0x20]!`, `#0x28`...
  a cctor builds several arrays (base64 chunks plus sibling GeneratedClrTypeInfo name arrays) so
  stores split into groups whenever the offset resets, and the group that decodes to a valid
  FileDescriptorProto is the descriptor

requires capstone pyelftools and protobuf

    python dump_protos.py --so libil2cpp.so --dump dump.cs --stringliterals stringliteral.json --out <region>/protobufs
"""
from __future__ import annotations

import argparse
import base64
import bisect
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile
from google.protobuf import descriptor_pb2


class Binary:
    def __init__(self, so_path: Path, stringliterals_path: Path) -> None:
        self._f = open(so_path, "rb")
        elf = ELFFile(self._f)
        self._segs = [
            (s["p_vaddr"], s["p_filesz"], s["p_offset"])
            for s in elf.iter_segments()
            if s["p_type"] == "PT_LOAD"
        ]
        self.relocs: dict[int, int] = {}
        for sec in elf.iter_sections():
            if sec.header["sh_type"] in (
                "SHT_RELA",
                "SHT_REL",
                "SHT_ANDROID_RELA",
                "SHT_ANDROID_REL",
            ):
                for r in sec.iter_relocations():
                    self.relocs[r["r_offset"]] = r.entry.get("r_addend", 0)

        data = json.loads(stringliterals_path.read_text(encoding="utf-8"))
        self.literals: dict[int, str] = {}
        for e in data:
            addr = e["address"]
            addr = int(addr, 16) if isinstance(addr, str) else addr
            self.literals[addr] = e["value"]

    def read(self, va: int, size: int) -> bytes:
        for vaddr, filesz, off in self._segs:
            if vaddr <= va < vaddr + filesz:
                self._f.seek(off + (va - vaddr))
                return self._f.read(size)
        return b""

    def chunk_at_slot(self, slot: int) -> str | None:
        # metadata-usage slot to reloc addend to string-literal value
        addend = self.relocs.get(slot)
        if addend is None:
            return None
        return self.literals.get(addend)


# dump.cs parsing

_CLASS = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*"
    r"(?:public|internal|private|protected)?\s*(?:static\s+)?(?:sealed\s+)?"
    r"(?:abstract\s+)?(?:partial\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_RVA = re.compile(
    r"//\s*RVA:\s*0x[0-9A-Fa-f]+\s*Offset:\s*0x[0-9A-Fa-f]+\s*VA:\s*(0x[0-9A-Fa-f]+)"
)
_METHOD = re.compile(r"(\.?[A-Za-z_][A-Za-z0-9_]*)\s*\(")


def parse_dump_cs(path: Path) -> tuple[list[int], dict[int, str]]:
    """(sorted method vas, {va: cctor_name}) for *Reflection classes, scope tracked by brace depth

    keyed by va, not name, since class names collide across namespaces (LiveGenReflection appears
    for both common/live and rpc/api/live)
    """
    all_vas: list[int] = []
    cctors: dict[int, str] = {}
    depth = 0
    class_stack: list[tuple[int, str]] = []
    pending_class: str | None = None
    pending_va: int | None = None

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cm = _CLASS.match(line)
        if cm:
            pending_class = cm.group(1)

        rm = _RVA.search(line)
        if rm:
            pending_va = int(rm.group(1), 16)
        elif pending_va is not None and "(" in line:
            nm = _METHOD.search(line)
            if nm:
                cur = class_stack[-1][1] if class_stack else None
                mname = nm.group(1)
                all_vas.append(pending_va)
                if mname == ".cctor" and cur and cur.endswith("Reflection"):
                    cctors[pending_va] = f"{cur}..cctor"
            pending_va = None

        opens, closes = line.count("{"), line.count("}")
        if pending_class and opens > 0:
            depth += 1
            class_stack.append((depth, pending_class))
            pending_class = None
            opens -= 1
        depth += opens
        for _ in range(closes):
            if class_stack and depth == class_stack[-1][0]:
                class_stack.pop()
            depth = max(0, depth - 1)

    all_vas.sort()
    return all_vas, cctors


# cctor disassembly to descriptor bytes

_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD.detail = True


def _chunk_groups(bin_: Binary, va: int, end: int) -> list[list[tuple[int, str]]]:
    """ordered string[] build groups of base64 chunks from one cctor

    page tracks the live adrp page per register, carry tracks which register holds a resolved chunk
    (propagated through `ldr xD,[xS]` and `mov`). stores of carried chunks are grouped, a new group
    starting whenever the array offset stops increasing
    """
    code = bin_.read(va, min(end - va, 0x10000))
    page: dict[int, int] = {}
    carry: dict[int, str] = {}
    groups: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] = []
    last_off: int | None = None

    for ins in _MD.disasm(code, va):
        mn = ins.mnemonic
        ops = ins.operands
        if mn == "ret":
            break

        if mn == "adrp":
            page[ops[0].reg] = ops[1].imm
            carry.pop(ops[0].reg, None)
            continue

        if mn == "ldr" and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            dst, base, disp = ops[0].reg, ops[1].mem.base, ops[1].mem.disp
            value: str | None = None
            if base in page:
                value = bin_.chunk_at_slot(page[base] + disp)
            elif base in carry and disp == 0:
                value = carry[base]
            page.pop(dst, None)
            if value is not None:
                carry[dst] = value
            else:
                carry.pop(dst, None)
            continue

        if (
            mn == "str"
            and len(ops) >= 2
            and ops[1].type == ARM64_OP_MEM
            and ops[0].reg in carry
        ):
            off = ops[1].mem.disp
            if last_off is not None and off <= last_off:
                groups.append(cur)
                cur = []
            cur.append((off, carry[ops[0].reg]))
            last_off = off
            continue

        if mn == "mov" and len(ops) == 2 and ops[1].type == ARM64_OP_REG:
            src = ops[1].reg
            if src in carry:
                carry[ops[0].reg] = carry[src]
            else:
                carry.pop(ops[0].reg, None)
            page.pop(ops[0].reg, None)
            continue

        # any other write clears tracked registers
        try:
            for r in ins.regs_access()[1]:
                page.pop(r, None)
                carry.pop(r, None)
        except OSError:
            pass

    if cur:
        groups.append(cur)
    return groups


def extract_descriptor(bin_: Binary, va: int, end: int):
    """parsed FileDescriptorProto for one cctor, or none if it is not one"""
    for group in _chunk_groups(bin_, va, end):
        b64 = "".join(v for _, v in sorted(group))
        if not b64:
            continue
        try:
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
            fdp = descriptor_pb2.FileDescriptorProto.FromString(raw)
        except Exception:
            continue
        if fdp.name.endswith(".proto"):
            return fdp, raw
    return None


# FileDescriptorProto to .proto text

FD = descriptor_pb2.FieldDescriptorProto
_SCALAR = {
    FD.TYPE_DOUBLE: "double",
    FD.TYPE_FLOAT: "float",
    FD.TYPE_INT64: "int64",
    FD.TYPE_UINT64: "uint64",
    FD.TYPE_INT32: "int32",
    FD.TYPE_FIXED64: "fixed64",
    FD.TYPE_FIXED32: "fixed32",
    FD.TYPE_BOOL: "bool",
    FD.TYPE_STRING: "string",
    FD.TYPE_GROUP: "group",
    FD.TYPE_BYTES: "bytes",
    FD.TYPE_UINT32: "uint32",
    FD.TYPE_SFIXED32: "sfixed32",
    FD.TYPE_SFIXED64: "sfixed64",
    FD.TYPE_SINT32: "sint32",
    FD.TYPE_SINT64: "sint64",
}


def _strip(name: str, package: str) -> str:
    # strip only the current package prefix, keep the leading dot on cross-package refs
    if package and name.startswith("." + package + "."):
        return name[len(package) + 2 :]
    return name


def _map_entries(msg) -> dict[str, tuple]:
    """map-entry nested name to (key_field, value_field)"""
    out = {}
    for nt in msg.nested_type:
        if nt.options.map_entry:
            key = next((f for f in nt.field if f.number == 1), None)
            val = next((f for f in nt.field if f.number == 2), None)
            if key and val:
                out[nt.name] = (key, val)
    return out


def _field_line(
    fd, package: str, maps: dict[str, tuple], proto2: bool, in_oneof: bool
) -> str:
    if fd.type == FD.TYPE_MESSAGE and fd.label == FD.LABEL_REPEATED:
        short = _strip(fd.type_name, package).rsplit(".", 1)[-1]
        if short in maps:
            key, val = maps[short]
            kt = _SCALAR.get(key.type, "int32")
            vt = (
                _strip(val.type_name, package)
                if val.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM)
                else _SCALAR.get(val.type, "int32")
            )
            return f"map<{kt}, {vt}> {fd.name} = {fd.number};"

    if fd.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM):
        typ = _strip(fd.type_name, package)
    else:
        typ = _SCALAR.get(fd.type, "unknown")

    # oneof members never carry a label
    label = ""
    if not in_oneof:
        if fd.label == FD.LABEL_REPEATED:
            label = "repeated "
        elif fd.label == FD.LABEL_REQUIRED:
            label = "required "
        elif fd.proto3_optional or (proto2 and fd.label == FD.LABEL_OPTIONAL):
            label = "optional "

    opts = []
    if fd.options.deprecated:
        opts.append("deprecated = true")
    if fd.options.packed:
        opts.append("packed = true")
    opt = f" [{', '.join(opts)}]" if opts else ""
    return f"{label}{typ} {fd.name} = {fd.number}{opt};"


def _print_enum(enum, name: str, indent: str, lines: list[str]) -> None:
    lines.append(f"{indent}enum {name} {{")
    if enum.options.allow_alias:
        lines.append(f"{indent}  option allow_alias = true;")
    for v in enum.value:
        lines.append(f"{indent}  {v.name} = {v.number};")
    lines.append(f"{indent}}}")


def _print_message(
    msg, package: str, proto2: bool, indent: str, lines: list[str]
) -> None:
    lines.append(f"{indent}message {msg.name} {{")
    inner = indent + "  "
    maps = _map_entries(msg)

    for en in msg.enum_type:
        _print_enum(en, en.name, inner, lines)
    for nt in msg.nested_type:
        if nt.options.map_entry:
            continue
        _print_message(nt, package, proto2, inner, lines)

    # group fields by oneof, skipping synthetic proto3-optional oneofs
    oneof_fields: dict[int, list] = {}
    plain = []
    for fd in msg.field:
        if fd.HasField("oneof_index") and not fd.proto3_optional:
            oneof_fields.setdefault(fd.oneof_index, []).append(fd)
        else:
            plain.append(fd)

    for fd in plain:
        lines.append(f"{inner}{_field_line(fd, package, maps, proto2, False)}")

    for idx, decl in enumerate(msg.oneof_decl):
        if idx not in oneof_fields:
            continue
        lines.append(f"{inner}oneof {decl.name} {{")
        for fd in oneof_fields[idx]:
            lines.append(f"{inner}  {_field_line(fd, package, maps, proto2, True)}")
        lines.append(f"{inner}}}")

    for rng in msg.reserved_range:
        hi = rng.end - 1
        lines.append(
            f"{inner}reserved {rng.start}{'' if rng.start == hi else f' to {hi}'};"
        )
    for nm in msg.reserved_name:
        lines.append(f'{inner}reserved "{nm}";')

    lines.append(f"{indent}}}")


_FILE_OPTS = [
    "java_package",
    "java_outer_classname",
    "go_package",
    "csharp_namespace",
    "objc_class_prefix",
]


def _render_defs(fdp) -> list[str]:
    """enum/message/service definitions only, no syntax/package/import/option preamble"""
    pkg = fdp.package
    proto2 = (fdp.syntax or "proto2") != "proto3"
    lines: list[str] = []

    for en in fdp.enum_type:
        _print_enum(en, en.name, "", lines)
        lines.append("")
    for msg in fdp.message_type:
        _print_message(msg, pkg, proto2, "", lines)
        lines.append("")

    for svc in fdp.service:
        lines.append(f"service {svc.name} {{")
        for m in svc.method:
            cs = "stream " if m.client_streaming else ""
            ss = "stream " if m.server_streaming else ""
            lines.append(
                f"  rpc {m.name} ({cs}{_strip(m.input_type, pkg)}) returns ({ss}{_strip(m.output_type, pkg)});"
            )
        lines.append("}")
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    return lines


def render_proto(fdp) -> str:
    pkg = fdp.package
    lines = [f'syntax = "{fdp.syntax or "proto2"}";', ""]
    if pkg:
        lines += [f"package {pkg};", ""]

    for dep in fdp.dependency:
        kw = (
            "import public"
            if fdp.dependency.index(dep) in fdp.public_dependency
            else "import"
        )
        lines.append(f'{kw} "{dep}";')
    if fdp.dependency:
        lines.append("")

    opt = fdp.options
    printed_opt = False
    for name in _FILE_OPTS:
        if opt.HasField(name):
            lines.append(f'option {name} = "{getattr(opt, name)}";')
            printed_opt = True
    if printed_opt:
        lines.append("")

    lines += _render_defs(fdp)

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


# merged.proto tree assembly
#
# merged.proto nests every descriptor under synthetic `message` blocks named after its
# directory path, e.g. "buf/validate/validate.proto" ends up under
#   message buf { message validate { ... } }
# so descriptors sharing a directory land inside the same nested block. files with no
# directory component (a bare "foo.proto") are emitted at the top level, unwrapped


def _build_merged_tree(descriptors: dict[str, tuple]) -> dict:
    root: dict = {}
    for name in descriptors:
        parts = name.split("/")
        node = root
        for d in parts[:-1]:
            node = node.setdefault(d, {})
        node.setdefault("__files__", []).append(name)
    return root


def _render_merged_tree(
    node: dict, indent: str, descriptors: dict[str, tuple], lines: list[str]
) -> None:
    for key in sorted(k for k in node if k != "__files__"):
        lines.append(f"{indent}message {key} {{")
        _render_merged_tree(node[key], indent + "  ", descriptors, lines)
        lines.append(f"{indent}}}")
        lines.append("")

    for name in sorted(node.get("__files__", [])):
        fdp, raw = descriptors[name]
        for line in _render_defs(fdp):
            lines.append(f"{indent}{line}" if line else "")
        lines.append("")


def render_merged(descriptors: dict[str, tuple]) -> str:
    tree = _build_merged_tree(descriptors)
    lines: list[str] = []
    _render_merged_tree(tree, "", descriptors, lines)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


# merged_flat.proto
#
# every type hoisted to the top level with the package folded into an underscore name
# (rpc.api.MasterGetResponse becomes rpc_api_MasterGetResponse) and all references rewritten
# to match, so there is no nesting and no packages


def _flat_ref(type_name: str) -> str:
    return type_name.lstrip(".").replace(".", "_")


def _flat_field_line(fd, maps: dict[str, tuple], proto2: bool, in_oneof: bool) -> str:
    if fd.type == FD.TYPE_MESSAGE and fd.label == FD.LABEL_REPEATED:
        short = fd.type_name.rsplit(".", 1)[-1]
        if short in maps:
            key, val = maps[short]
            kt = _SCALAR.get(key.type, "int32")
            vt = (
                _flat_ref(val.type_name)
                if val.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM)
                else _SCALAR.get(val.type, "int32")
            )
            return f"map<{kt}, {vt}> {fd.name} = {fd.number};"

    if fd.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM):
        typ = _flat_ref(fd.type_name)
    else:
        typ = _SCALAR.get(fd.type, "unknown")

    label = ""
    if not in_oneof:
        if fd.label == FD.LABEL_REPEATED:
            label = "repeated "
        elif fd.label == FD.LABEL_REQUIRED:
            label = "required "
        elif fd.proto3_optional or (proto2 and fd.label == FD.LABEL_OPTIONAL):
            label = "optional "

    opts = []
    if fd.options.deprecated:
        opts.append("deprecated = true")
    if fd.options.packed:
        opts.append("packed = true")
    opt = f" [{', '.join(opts)}]" if opts else ""
    return f"{label}{typ} {fd.name} = {fd.number}{opt};"


def _flat_message(flat: str, msg, proto2: bool, lines: list[str]) -> None:
    maps = _map_entries(msg)
    lines.append(f"message {flat} {{")

    oneof_fields: dict[int, list] = {}
    plain = []
    for fd in msg.field:
        if fd.HasField("oneof_index") and not fd.proto3_optional:
            oneof_fields.setdefault(fd.oneof_index, []).append(fd)
        else:
            plain.append(fd)

    for fd in plain:
        lines.append(f"  {_flat_field_line(fd, maps, proto2, False)}")

    for idx, decl in enumerate(msg.oneof_decl):
        if idx not in oneof_fields:
            continue
        lines.append(f"  oneof {decl.name} {{")
        for fd in oneof_fields[idx]:
            lines.append(f"    {_flat_field_line(fd, maps, proto2, True)}")
        lines.append("  }")

    for rng in msg.reserved_range:
        hi = rng.end - 1
        lines.append(f"  reserved {rng.start}{'' if rng.start == hi else f' to {hi}'};")
    for nm in msg.reserved_name:
        lines.append(f'  reserved "{nm}";')

    lines.append("}")


def _collect_flat(msg, prefix: str, proto2: bool, messages: list, enums: list) -> None:
    flat = prefix + msg.name
    messages.append((flat, msg, proto2))
    for en in msg.enum_type:
        enums.append((flat + "_" + en.name, en))
    for nt in msg.nested_type:
        if not nt.options.map_entry:
            _collect_flat(nt, flat + "_", proto2, messages, enums)


def render_merged_flat(descriptors: dict[str, tuple]) -> str:
    enums: list[tuple] = []
    messages: list[tuple] = []
    services: list[tuple] = []

    for name in sorted(descriptors):
        fdp, _ = descriptors[name]
        proto2 = (fdp.syntax or "proto2") != "proto3"
        prefix = (fdp.package.replace(".", "_") + "_") if fdp.package else ""
        for en in fdp.enum_type:
            enums.append((prefix + en.name, en))
        for msg in fdp.message_type:
            _collect_flat(msg, prefix, proto2, messages, enums)
        for svc in fdp.service:
            services.append((prefix + svc.name, svc))

    lines: list[str] = []
    for flat, en in sorted(enums, key=lambda t: t[0]):
        _print_enum(en, flat, "", lines)
        lines.append("")
    for flat, msg, proto2 in sorted(messages, key=lambda t: t[0]):
        _flat_message(flat, msg, proto2, lines)
        lines.append("")
    for flat, svc in sorted(services, key=lambda t: t[0]):
        lines.append(f"service {flat} {{")
        for m in svc.method:
            cs = "stream " if m.client_streaming else ""
            ss = "stream " if m.server_streaming else ""
            lines.append(
                f"  rpc {m.name} ({cs}{_flat_ref(m.input_type)}) returns ({ss}{_flat_ref(m.output_type)});"
            )
        lines.append("}")
        lines.append("")

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


# driver


def dump(so: Path, dump_cs: Path, stringliterals: Path, out: Path) -> int:
    """extract all descriptors and write the output tree, raising on any failure"""
    bin_ = Binary(so, stringliterals)
    method_vas, cctors = parse_dump_cs(dump_cs)
    if not cctors:
        raise RuntimeError("no *Reflection..cctor found in dump.cs")

    descriptors: dict[str, tuple] = {}
    for va in cctors:
        i = bisect.bisect_right(method_vas, va)
        end = method_vas[i] if i < len(method_vas) else va + 0x8000
        result = extract_descriptor(bin_, va, end)
        if result is not None:
            fdp, raw = result
            descriptors[fdp.name] = (fdp, raw)

    if not descriptors:
        raise RuntimeError(
            "no FileDescriptorProto extracted, extraction logic may be stale"
        )

    out.mkdir(parents=True, exist_ok=True)
    for old in out.rglob("*.proto"):
        old.unlink()

    base64_lines = []
    for name in sorted(descriptors):
        fdp, raw = descriptors[name]
        dest = out / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render_proto(fdp), encoding="utf-8")
        base64_lines.append(f"{name}\t{base64.b64encode(raw).decode()}")

    (out / "all_base64.txt").write_text(
        "\n".join(base64_lines) + "\n", encoding="utf-8"
    )
    (out / "merged.proto").write_text(render_merged(descriptors), encoding="utf-8")
    (out / "merged_flat.proto").write_text(
        render_merged_flat(descriptors), encoding="utf-8"
    )
    return len(descriptors)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--so", required=True, type=Path)
    ap.add_argument("--dump", required=True, type=Path)
    ap.add_argument("--stringliterals", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    count = dump(args.so, args.dump, args.stringliterals, args.out)
    print(f"[dump_protos] extracted {count} descriptors -> {args.out}")


if __name__ == "__main__":
    main()
