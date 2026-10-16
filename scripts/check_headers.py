#!/usr/bin/env python3
"""Check the catalogue, includes, example references and header compilation."""

import argparse
import collections
import concurrent.futures
import math
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


LEXEMES = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.DOTALL)
CALLER_TYPES = {
    "bit", "int", "varbit", "bool", "string", "void", "error", "packet_in",
    "packet_out", "standard_metadata_t", "headers", "metadata",
}

WRAPPER = """
header LibraryCheckEthernet {
    bit<48> destination;
    bit<48> source;
    bit<16> ether_type;
}
struct LibraryCheckHeaders { LibraryCheckEthernet ethernet; }
struct LibraryCheckMetadata { bit<1> unused; }
parser LibraryCheckParser(packet_in pkt, out LibraryCheckHeaders hdr,
                         inout LibraryCheckMetadata meta,
                         inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}
control LibraryCheckVerify(inout LibraryCheckHeaders hdr,
                          inout LibraryCheckMetadata meta) { apply {} }
control LibraryCheckIngress(inout LibraryCheckHeaders hdr,
                           inout LibraryCheckMetadata meta,
                           inout standard_metadata_t sm) {
    apply {
        if (sm.parser_error != error.NoError) { mark_to_drop(sm); }
        else { sm.egress_spec = 2; }
    }
}
control LibraryCheckEgress(inout LibraryCheckHeaders hdr,
                          inout LibraryCheckMetadata meta,
                          inout standard_metadata_t sm) { apply {} }
control LibraryCheckCompute(inout LibraryCheckHeaders hdr,
                           inout LibraryCheckMetadata meta) { apply {} }
control LibraryCheckDeparser(packet_out pkt, in LibraryCheckHeaders hdr) {
    apply { pkt.emit(hdr.ethernet); }
}
V1Switch(LibraryCheckParser(), LibraryCheckVerify(), LibraryCheckIngress(),
         LibraryCheckEgress(), LibraryCheckCompute(), LibraryCheckDeparser()) main;
"""


def strip_comments(text):
    def replace(match):
        token = match.group()
        if token.startswith('"'):
            return token
        return re.sub(r"[^\n]", " ", token)

    return LEXEMES.sub(replace, text)


def code_identifiers(text):
    return LEXEMES.sub(lambda m: " " if m.group().startswith('"') else m.group(),
                       strip_comments(text))


def symbols(text):
    types = set(re.findall(
        r"^\s*(?:header|header_union|struct|enum)\s+(?:bit<\d+>\s+)?(\w+)",
        text, re.MULTILINE))
    types.update(re.findall(r"\btypedef\s+[^;]+?\s+(\w+)\s*;", text))
    names = types | set(re.findall(r"\bconst\s+[^;=]+?\s+(\w+)\s*=", text))
    enums = {}
    for name, body in re.findall(
            r"\benum\s+(?:bit<\d+>\s+)?(\w+)\s*\{([^}]*)\}", text):
        enums[name] = set(re.findall(r"(?:^|,)\s*(\w+)", body))
    return names, enums, types


def check_references(root, sources):
    errors = []
    readme = (root / "README.md").read_text(encoding="utf-8")
    listed = re.findall(r"^\|\s*`([^`]+\.p4)`\s*\|", readme, re.MULTILINE)
    for name in sorted(set(sources) - set(listed)):
        errors.append(f"README.md: missing catalogue entry for {name}")
    for name in sorted(set(listed) - set(sources)):
        errors.append(f"README.md: catalogue file does not exist: {name}")
    for name, count in collections.Counter(listed).items():
        if count > 1:
            errors.append(f"README.md: duplicate catalogue entry for {name}")
    for pattern in (r"\b(\d+) P4 files\b", r"(\d+)\s*个 P4 文件"):
        for count in re.findall(pattern, readme):
            if int(count) != len(sources):
                errors.append(f"README.md: file count {count}, expected {len(sources)}")
    for name in re.findall(r'#include\s+"([^"\n]+)"', readme):
        if not (root / name).is_file():
            errors.append(f"README.md: missing include {name}")

    graph = {}
    definitions = {}
    enumerations = {}
    type_definitions = {}
    guards = {}
    for name, source in sources.items():
        clean = strip_comments(source)
        definitions[name], enumerations[name], type_definitions[name] = symbols(
            code_identifiers(source))
        guard = re.search(
            r"^\s*#ifndef\s+(\w+)\s*\n\s*#define\s+(\w+)\b", clean,
            re.MULTILINE)
        if not guard or guard[1] != guard[2]:
            errors.append(f"{name}: missing or inconsistent include guard")
        elif guard[1] in guards:
            errors.append(f"{name}: include guard also used by {guards[guard[1]]}")
        else:
            guards[guard[1]] = name
        graph[name] = set()
        for include in re.findall(r'^\s*#include\s+"([^"\n]+)"', clean,
                                  re.MULTILINE):
            target = (root / include).resolve()
            if target.parent != root or target.name not in sources:
                errors.append(f"{name}: missing library include {include}")
            else:
                graph[name].add(target.name)

    closures = {}

    def visit(name, stack):
        if name in stack:
            errors.append("include cycle: " + " -> ".join((*stack, name)))
            return set()
        if name not in closures:
            reachable = {name}
            for child in sorted(graph[name]):
                reachable.update(visit(child, (*stack, name)))
            closures[name] = reachable
        return closures[name]

    for name in sources:
        visit(name, ())
    if errors:
        return errors, sum(map(len, graph.values())), 0

    examples = 0
    for name, source in sources.items():
        visible = set().union(*(definitions[p] for p in closures[name]))
        visible_types = set().union(*(type_definitions[p] for p in closures[name]))
        enums = {key: value for p in sorted(closures[name])
                 for key, value in enumerations[p].items()}
        for match in LEXEMES.finditer(source):
            token = match.group()
            if not token.startswith("/*"):
                continue
            code = code_identifiers(token[2:-2])
            if not re.search(r"^\s*(?:parser|control)\s+\w+", code, re.MULTILINE):
                continue
            examples += 1
            local, local_enums, local_types = symbols(code)
            allowed_types = visible_types | CALLER_TYPES | local_types
            local.update(member for members in local_enums.values() for member in members)
            local.update(re.findall(r"\b(?:parser|control|action|table|state)\s+(\w+)",
                                    code))
            for typ, parameter in re.findall(
                    r"\b(?:in|out|inout)\s+(\w+)(?:<[^>]+>)?(?:\[\d+\])?\s+(\w+)",
                    code):
                if typ not in allowed_types:
                    errors.append(f"{name}: unknown example parameter type {typ}")
                local.add(parameter)
            for typ, variable in re.findall(
                    r"(?=\b(\w+)(?:<[^>\n]+>)?(?:\[\d+\])?\s+(\w+)\b)", code):
                if typ in allowed_types:
                    local.add(variable)
            for typ, member in re.findall(r"\b(\w+)\.(\w+)\b", code):
                members = local_enums.get(typ, enums.get(typ))
                if members is not None and member not in members:
                    errors.append(f"{name}: unknown example enum member {typ}.{member}")
            for constant in sorted(set(re.findall(
                    r"(?<![\w.])\b[A-Z][A-Z0-9_]+\b", code)) - visible - local):
                errors.append(f"{name}: unknown example constant {constant}")
    return errors, sum(map(len, graph.values())), examples


def compile_headers(sources, compilers, jobs, timeout):
    names = list(sources)
    variants = [(f"single-{Path(name).stem}", [name]) for name in names]
    shuffled = names.copy()
    random.Random(72416).shuffle(shuffled)
    variants.extend([
        ("all-sorted", names),
        ("all-reversed", list(reversed(names))),
        ("all-repeated", shuffled + names + list(reversed(names))),
    ])
    with tempfile.TemporaryDirectory(prefix="p4-headers-check-") as directory:
        work = Path(directory)
        include_dir = work / "include"
        include_dir.mkdir()
        for name, source in sources.items():
            (include_dir / name).write_text(source, encoding="utf-8")
        for name, includes in variants:
            source = '#include <core.p4>\n#include <v1model.p4>\n'
            source += "".join(f'#include "{path}"\n' for path in includes)
            (work / f"{name}.p4").write_text(source + WRAPPER, encoding="utf-8")

        def compile_one(task):
            name, compiler, executable = task
            command = [executable, "--std", "p4-16", "--Wdisable=unused", "--Werror",
                       "-I", "include", f"{name}.p4"]
            if compiler == "p4c-bm2-ss":
                command.extend(["-o", f"{name}.json"])
            try:
                result = subprocess.run(command, cwd=work, capture_output=True,
                                        encoding="utf-8", errors="replace",
                                        timeout=timeout)
            except subprocess.TimeoutExpired:
                return f"{name} ({compiler}): exceeded {timeout:g} seconds"
            except OSError as exc:
                return f"{name} ({compiler}): {exc}"
            if result.returncode:
                return (f"{name} ({compiler}): exit {result.returncode}\n"
                        f"{shlex.join(command)}\n{result.stdout}{result.stderr}")
            return None

        tasks = [(name, compiler, executable) for name, _ in variants
                 for compiler, executable in compilers.items()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(compile_one, tasks))
    failures = [result for result in results if result is not None]
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"Compilation: {len(tasks) - len(failures)}/{len(tasks)} checks passed "
          f"({len(names)} single-file and 3 combined programs, 2 compilers).")
    return not failures


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_seconds(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="library directory (default: script's repository)")
    parser.add_argument("--references-only", action="store_true",
                        help="check references without invoking compilers")
    parser.add_argument("--jobs", type=positive_int,
                        default=min(4, os.cpu_count() or 1),
                        help="parallel compiler processes (default: up to 4)")
    parser.add_argument("--timeout", type=positive_seconds, default=60.0,
                        help="seconds allowed per compilation (default: 60)")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        sources = {path.name: path.read_text(encoding="utf-8")
                   for path in sorted(root.glob("*.p4"))}
        if not sources:
            parser.error(f"no P4 files in {root}")
        errors, includes, examples = check_references(root, sources)
    except (OSError, UnicodeError) as exc:
        print(f"Reference check failed: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in sorted(set(errors)):
            print(error, file=sys.stderr)
        return 1
    print(f"References: {len(sources)} files, {includes} includes and "
          f"{examples} example blocks checked.", flush=True)
    if args.references_only:
        return 0
    compilers = {name: shutil.which(name) for name in ("p4test", "p4c-bm2-ss")}
    missing = [name for name, path in compilers.items() if path is None]
    if missing:
        print("Missing compiler(s): " + ", ".join(missing), file=sys.stderr)
        return 2
    return 0 if compile_headers(sources, compilers,
                                args.jobs, args.timeout) else 1


if __name__ == "__main__":
    sys.exit(main())
