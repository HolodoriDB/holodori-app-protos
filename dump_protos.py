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
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory


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


# option resolution
#
# custom options are extensions stored as unknown fields on the options message. a DescriptorPool
# built from every descriptor (force-built so extensions register) resolves them by number, and
# each is expanded to the aggregate scalar-leaf form, e.g.
#   (buf.validate.field).enum.defined_only = true

FD = descriptor_pb2.FieldDescriptorProto

_pool: descriptor_pool.DescriptorPool | None = None
_getcls = None


def _build_pool(descriptors: dict[str, tuple]) -> None:
    global _pool, _getcls
    pool = descriptor_pool.DescriptorPool()
    added: set[str] = set()

    def add(name: str) -> None:
        if name in added or name not in descriptors:
            return
        added.add(name)
        for dep in descriptors[name][0].dependency:
            add(dep)
        try:
            pool.Add(descriptors[name][0])
        except Exception:
            pass

    for name in descriptors:
        add(name)
    for name in descriptors:
        try:
            pool.FindFileByName(name)  # force build so extensions register by number
        except Exception:
            pass

    try:
        getcls = message_factory.GetMessageClass
    except AttributeError:
        mf = message_factory.MessageFactory(pool)
        getcls = mf.GetPrototype
    _pool, _getcls = pool, getcls


def _opt_scalar(fd, v) -> str:
    if fd.type == fd.TYPE_ENUM:
        ev = fd.enum_type.values_by_number.get(v)
        return ev.name if ev else str(v)
    if fd.type == fd.TYPE_BOOL:
        return "true" if v else "false"
    if fd.type == fd.TYPE_STRING:
        v = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else v
        return '"%s"' % v
    if fd.type == fd.TYPE_BYTES:
        v = v if isinstance(v, (bytes, bytearray)) else bytes(v)
        return '"%s"' % v.decode("latin1")
    return str(v)


def _opt_expand(prefix: str, msg, out: list[str]) -> None:
    for fd, val in msg.ListFields():
        nm = f"{prefix}.{fd.name}"
        for v in val if fd.label == fd.LABEL_REPEATED else [val]:
            if fd.type == fd.TYPE_MESSAGE:
                _opt_expand(nm, v, out)
            else:
                out.append(f"{nm} = {_opt_scalar(fd, v)}")


def _option_entries(opts, opts_fullname: str) -> list[str]:
    """aggregate scalar-leaf entries for one options message, standard fields then extensions"""
    if _pool is None:
        return []
    try:
        desc = _pool.FindMessageTypeByName(opts_fullname)
    except KeyError:
        return []
    out: list[str] = []
    for fd, val in opts.ListFields():
        for v in val if fd.label == fd.LABEL_REPEATED else [val]:
            if fd.type == fd.TYPE_MESSAGE:
                _opt_expand(fd.name, v, out)
            else:
                out.append(f"{fd.name} = {_opt_scalar(fd, v)}")
    # custom options (extensions) are sorted by name, standard options above come first
    exts = []
    for u in opts.UnknownFields():
        try:
            exts.append((_pool.FindExtensionByNumber(desc, u.field_number), u))
        except KeyError:
            continue
    for ext, u in sorted(exts, key=lambda e: e[0].full_name):
        base = f"({ext.full_name})"
        if ext.type == ext.TYPE_MESSAGE:
            sub = _getcls(ext.message_type)()
            sub.ParseFromString(bytes(u.data))
            _opt_expand(base, sub, out)
        else:
            data = u.data
            if ext.type == ext.TYPE_STRING:
                data = bytes(data).decode("utf-8")
            elif ext.type == ext.TYPE_BYTES:
                data = bytes(data)
            out.append(f"{base} = {_opt_scalar(ext, data)}")
    return out


# FileDescriptorProto to .proto text

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
    # strip only the current-or-descendant package prefix, keep the leading dot on unrelated refs
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
    fd,
    package: str,
    maps: dict[str, tuple],
    proto2: bool,
    in_oneof: bool,
    full_qualify: bool = False,
) -> str:
    def ref(tn: str) -> str:
        return tn if full_qualify else _strip(tn, package)

    if fd.type == FD.TYPE_MESSAGE and fd.label == FD.LABEL_REPEATED:
        short = _strip(fd.type_name, package).rsplit(".", 1)[-1]
        if short in maps:
            key, val = maps[short]
            kt = _SCALAR.get(key.type, "int32")
            vt = (
                ref(val.type_name)
                if val.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM)
                else _SCALAR.get(val.type, "int32")
            )
            decl = f"map<{kt}, {vt}> {fd.name} = {fd.number}"
            opts = _option_entries(fd.options, "google.protobuf.FieldOptions")
            return decl + (f" [{', '.join(opts)}]" if opts else "") + ";"

    if fd.type in (FD.TYPE_MESSAGE, FD.TYPE_ENUM):
        typ = ref(fd.type_name)
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

    opts = _option_entries(fd.options, "google.protobuf.FieldOptions")
    tail = f" [{', '.join(opts)}]" if opts else ""
    return f"{label}{typ} {fd.name} = {fd.number}{tail};"


def _join_blocks(blocks: list[list[str]]) -> list[str]:
    """flatten non-empty blocks, one blank line between each"""
    out: list[str] = []
    for b in (b for b in blocks if b):
        if out:
            out.append("")
        out.extend(b)
    return out


def _extend_blocks(package: str, exts, proto2: bool, indent: str) -> list[list[str]]:
    groups: dict[str, list] = {}
    order: list[str] = []
    for ext in exts:
        if ext.extendee not in groups:
            groups[ext.extendee] = []
            order.append(ext.extendee)
        groups[ext.extendee].append(ext)
    blocks = []
    for extendee in order:
        b = [f"{indent}extend {extendee.lstrip('.')} {{"]
        b += [
            f"{indent}\t{_field_line(e, package, {}, proto2, False)}"
            for e in groups[extendee]
        ]
        b.append(f"{indent}}}")
        blocks.append(b)
    return blocks


def _render_enum(enum, indent: str, prefix: str = "") -> list[str]:
    inner = indent + "\t"
    blocks: list[list[str]] = []
    opts = [
        f"{inner}option {e};"
        for e in _option_entries(enum.options, "google.protobuf.EnumOptions")
    ]
    if opts:
        blocks.append(opts)
    values = []
    for v in enum.value:
        vo = _option_entries(v.options, "google.protobuf.EnumValueOptions")
        tail = f" [{', '.join(vo)}]" if vo else ""
        values.append(f"{inner}{prefix}{v.name} = {v.number}{tail};")
    if values:
        blocks.append(values)
    return [f"{indent}enum {enum.name} {{", *_join_blocks(blocks), f"{indent}}}"]


def _render_message(
    msg,
    package: str,
    proto2: bool,
    indent: str,
    full_qualify: bool = False,
    prefix_enums: bool = False,
) -> list[str]:
    inner = indent + "\t"
    maps = _map_entries(msg)
    blocks: list[list[str]] = []

    opts = [
        f"{inner}option {e};"
        for e in _option_entries(msg.options, "google.protobuf.MessageOptions")
    ]
    if opts:
        blocks.append(opts)

    # nested types precede fields
    for nt in msg.nested_type:
        if not nt.options.map_entry:
            blocks.append(
                _render_message(nt, package, proto2, inner, full_qualify, prefix_enums)
            )
    for en in msg.enum_type:
        blocks.append(_render_enum(en, inner, f"{en.name}_" if prefix_enums else ""))
    if msg.extension:
        blocks += _extend_blocks(package, msg.extension, proto2, inner)

    oneof_fields: dict[int, list] = {}
    plain = []
    for fd in msg.field:
        if fd.HasField("oneof_index") and not fd.proto3_optional:
            oneof_fields.setdefault(fd.oneof_index, []).append(fd)
        else:
            plain.append(fd)
    if plain:
        blocks.append(
            [
                f"{inner}{_field_line(fd, package, maps, proto2, False, full_qualify)}"
                for fd in plain
            ]
        )
    for idx, decl in enumerate(msg.oneof_decl):
        if idx not in oneof_fields:
            continue
        b = [f"{inner}oneof {decl.name} {{"]
        b += [
            f"{inner}\t{_field_line(fd, package, maps, proto2, True, full_qualify)}"
            for fd in oneof_fields[idx]
        ]
        b.append(f"{inner}}}")
        blocks.append(b)

    reserved = []
    for rng in msg.reserved_range:
        hi = rng.end - 1
        reserved.append(
            f"{inner}reserved {rng.start}{'' if rng.start == hi else f' to {hi}'};"
        )
    for nm in msg.reserved_name:
        reserved.append(f'{inner}reserved "{nm}";')
    if reserved:
        blocks.append(reserved)

    return [f"{indent}message {msg.name} {{", *_join_blocks(blocks), f"{indent}}}"]


def _render_service(svc, name: str | None = None, indent: str = "") -> list[str]:
    inner = indent + "\t"
    blocks: list[list[str]] = []
    sopts = [
        f"{inner}option {e};"
        for e in _option_entries(svc.options, "google.protobuf.ServiceOptions")
    ]
    if sopts:
        blocks.append(sopts)
    # a method with an option body is its own block, runs of simple methods group together
    simple: list[str] = []
    for m in svc.method:
        cs = "stream " if m.client_streaming else ""
        ss = "stream " if m.server_streaming else ""
        head = f"{inner}rpc {m.name} ({cs}{m.input_type}) returns ({ss}{m.output_type})"
        mopts = _option_entries(m.options, "google.protobuf.MethodOptions")
        if mopts:
            if simple:
                blocks.append(simple)
                simple = []
            blocks.append(
                [head + " {", *[f"{inner}\toption {e};" for e in mopts], f"{inner}}}"]
            )
        else:
            simple.append(head + ";")
    if simple:
        blocks.append(simple)
    return [
        f"{indent}service {name or svc.name} {{",
        *_join_blocks(blocks),
        f"{indent}}}",
    ]


def render_proto(fdp) -> str:
    pkg = fdp.package
    proto2 = (fdp.syntax or "proto2") != "proto3"
    blocks: list[list[str]] = []
    if not proto2:  # proto2 is the default and its syntax line is omitted
        blocks.append(['syntax = "proto3";'])
    if fdp.dependency:
        public = set(fdp.public_dependency)
        blocks.append(
            [
                f'import {"public " if isp else ""}"{dep}";'
                for dep, isp in sorted(
                    (d, i in public) for i, d in enumerate(fdp.dependency)
                )
            ]
        )
    if pkg:
        blocks.append([f"package {pkg};"])
    fopts = [
        f"option {e};"
        for e in _option_entries(fdp.options, "google.protobuf.FileOptions")
    ]
    if fopts:
        blocks.append(fopts)
    if fdp.extension:
        blocks += _extend_blocks(pkg, fdp.extension, proto2, "")
    for en in fdp.enum_type:
        blocks.append(_render_enum(en, ""))
    for msg in fdp.message_type:
        blocks.append(_render_message(msg, pkg, proto2, ""))
    for svc in fdp.service:
        blocks.append(_render_service(svc))

    return "\n".join(_join_blocks(blocks)) + "\n"


# merged views


def render_merged(descriptors: dict[str, tuple]) -> str:
    """every descriptor's defs nested under synthetic message blocks named after its directory path"""
    tree: dict = {}
    for name in descriptors:
        node = tree
        for seg in name.split("/")[:-1]:
            node = node.setdefault(seg, {})
        node.setdefault("__files__", []).append(name)

    def render(node: dict, indent: str) -> list[str]:
        blocks: list[list[str]] = []
        for seg in sorted(k for k in node if k != "__files__"):
            blocks.append(
                [
                    f"{indent}message {seg} {{",
                    *render(node[seg], indent + "\t"),
                    f"{indent}}}",
                ]
            )
        for name in sorted(node.get("__files__", [])):
            fdp = descriptors[name][0]
            proto2 = (fdp.syntax or "proto2") != "proto3"
            for en in fdp.enum_type:
                blocks.append(_render_enum(en, indent))
            for msg in fdp.message_type:
                blocks.append(_render_message(msg, fdp.package, proto2, indent))
            for svc in fdp.service:
                blocks.append(_render_service(svc, indent=indent))
        return _join_blocks(blocks)

    return "\n".join(render(tree, "")) + "\n"


def render_merged_flat(descriptors: dict[str, tuple]) -> str:
    """one proto2 file: packages nested as message blocks (recreating fully-qualified names),
    services hoisted to the top level with flat names, enum values prefixed to avoid collisions,
    google/protobuf well-known types imported rather than nested"""
    from collections import defaultdict

    imported = sorted(n for n in descriptors if n.startswith("google/protobuf/"))
    skip = set(imported)
    msgs: dict[str, list] = defaultdict(list)
    enums: dict[str, list] = defaultdict(list)
    exts: dict[str, list] = defaultdict(list)
    services: list[tuple[str, object]] = []
    for name in sorted(descriptors):
        if name in skip:
            continue
        fdp = descriptors[name][0]
        p = fdp.package
        msgs[p] += list(fdp.message_type)
        enums[p] += list(fdp.enum_type)
        exts[p] += list(fdp.extension)
        prefix = (p.replace(".", "_") + "_") if p else ""
        for svc in fdp.service:
            services.append((prefix + svc.name, svc))

    tree: dict = {}
    for p in set(msgs) | set(enums) | set(exts):
        node = tree
        for seg in (p.split(".") if p else []):
            node = node.setdefault(seg, {})
        node["__pkg__"] = p

    def defs(p: str, indent: str) -> list[list[str]]:
        blocks: list[list[str]] = []
        blocks += _extend_blocks(p, exts[p], True, indent)
        for en in enums[p]:
            blocks.append(_render_enum(en, indent, f"{en.name}_"))
        for msg in msgs[p]:
            blocks.append(
                _render_message(
                    msg, p, True, indent, full_qualify=True, prefix_enums=True
                )
            )
        return blocks

    def render(node: dict, indent: str) -> list[str]:
        blocks: list[list[str]] = []
        if "__pkg__" in node:
            blocks += defs(node["__pkg__"], indent)
        for seg in sorted(k for k in node if k != "__pkg__"):
            blocks.append(
                [
                    f"{indent}message {seg} {{",
                    *render(node[seg], indent + "\t"),
                    f"{indent}}}",
                ]
            )
        return _join_blocks(blocks)

    top: list[list[str]] = [['syntax = "proto2";']]
    if imported:
        top.append([f'import "{n}";' for n in imported])
    body = render(tree, "")
    if body:
        top.append(body)
    for flat, svc in sorted(services, key=lambda t: t[0]):
        top.append(_render_service(svc, name=flat))
    return "\n".join(_join_blocks(top)) + "\n"


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

    _build_pool(descriptors)

    out.mkdir(parents=True, exist_ok=True)
    for old in out.rglob("*.proto"):
        old.unlink()

    base64_lines = []
    for name in sorted(descriptors):
        fdp, raw = descriptors[name]
        dest = out / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render_proto(fdp), encoding="utf-8", newline="\n")
        base64_lines.append(f"{name}\t{base64.b64encode(raw).decode()}")

    (out / "all_base64.txt").write_text(
        "\n".join(base64_lines) + "\n", encoding="utf-8", newline="\n"
    )
    (out / "merged.proto").write_text(
        render_merged(descriptors), encoding="utf-8", newline="\n"
    )
    (out / "merged_flat.proto").write_text(
        render_merged_flat(descriptors), encoding="utf-8", newline="\n"
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
