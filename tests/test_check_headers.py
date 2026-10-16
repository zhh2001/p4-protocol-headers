"""Run with: python3 -B -m unittest discover -s tests -v"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts" / "check_headers.py"
SPEC = importlib.util.spec_from_file_location("check_headers", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

DEFINITIONS = """
header TestHeader { bit<8> value; }
typedef bit<16> test_length_t;
const bit<8> TEST_PROTOCOL = 17;
enum bit<8> TestKind { DATA = 1, CONTROL = 2 }
"""

EXAMPLE = """
/*
parser ExampleParser(packet_in pkt, out TestHeader hdr,
                     inout metadata meta,
                     inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr);
        transition select(hdr.value) {
            TEST_PROTOCOL: accept;
            default: reject;
        }
    }
}
control ExampleControl(in TestKind kind, out test_length_t length) {
    apply {
        if (kind == TestKind.DATA) { length = (test_length_t)TEST_PROTOCOL; }
    }
}
*/
"""

FAKE_COMPILER = """
import json
import os
from pathlib import Path
import re
import sys
import time

compiler = Path(sys.argv[0]).name
source = Path(next(arg for arg in sys.argv[1:] if arg.endswith('.p4')))
includes = re.findall(r'^#include "([^"]+)"', source.read_text(), re.MULTILINE)
record = {
    'compiler': compiler,
    'args': sys.argv[1:],
    'cwd': str(Path.cwd()),
    'includes': includes,
    'sources': {name: (Path('include') / name).read_text() for name in includes},
}
with open(os.environ['HEADER_CHECK_TEST_LOG'], 'a', encoding='utf-8') as log:
    log.write(json.dumps(record) + '\\n')
mode = os.environ.get('HEADER_CHECK_TEST_MODE', 'success')
if compiler == 'p4test':
    if mode == 'failure':
        print('compiler output')
        print('compiler diagnostic', file=sys.stderr)
        sys.exit(17)
    if mode == 'timeout':
        time.sleep(5)
if '-o' in sys.argv:
    Path(sys.argv[sys.argv.index('-o') + 1]).write_text('{}')
"""


def guarded(name, body=""):
    guard = name.replace(".", "_").upper()
    return f"#ifndef {guard}\n#define {guard}\n{body}\n#endif\n"


class HeaderCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="p4-header-tests-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.bin = self.work / "compiler tools"
        self.builds = self.work / "build files"
        self.bin.mkdir()
        self.builds.mkdir()
        self.log = self.work / "compiler calls.jsonl"
        self.environment = dict(os.environ, PATH=str(self.bin), TMPDIR=str(self.builds),
                                HEADER_CHECK_TEST_LOG=str(self.log),
                                HEADER_CHECK_TEST_MODE="success")

    def library(self, sources, readme=None):
        root = Path(tempfile.mkdtemp(prefix="library with spaces ", dir=self.work))
        for name, source in sources.items():
            (root / name).write_text(source, encoding="utf-8")
        if readme is None:
            readme = f"{len(sources)} P4 files\n{len(sources)} 个 P4 文件\n"
            readme += "".join(f"| `{name}` | Test |\n" for name in sources)
        (root / "README.md").write_text(readme, encoding="utf-8")
        return root

    def references(self, sources, readme=None):
        return checker.check_references(self.library(sources, readme), sources)

    def run_check(self, root=None, *options):
        command = [sys.executable, "-B", str(SCRIPT)]
        if root is not None:
            command.extend(["--root", str(root)])
        command.extend(options)
        return subprocess.run(command, cwd=self.work, env=self.environment,
                              capture_output=True, encoding="utf-8", timeout=20)

    def install_compilers(self):
        for name in ("p4test", "p4c-bm2-ss"):
            path = self.bin / name
            path.write_text(f"#!{sys.executable}\n" + FAKE_COMPILER, encoding="utf-8")
            path.chmod(0o755)

    def compiler_calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_transitive_includes_supply_example_symbols(self):
        sources = {
            "a.p4": guarded("a.p4", '#include "./b.p4"\n' + EXAMPLE),
            "b.p4": guarded("b.p4", '#include "c.p4"'),
            "c.p4": guarded("c.p4", DEFINITIONS),
        }
        self.assertEqual(self.references(sources), ([], 2, 1))

    def test_sibling_symbols_require_an_include(self):
        sources = {"a.p4": guarded("a.p4", EXAMPLE),
                   "b.p4": guarded("b.p4", DEFINITIONS)}
        errors, includes, examples = self.references(sources)
        for message in ("unknown example parameter type TestHeader",
                        "unknown example parameter type TestKind",
                        "unknown example parameter type test_length_t",
                        "unknown example constant TEST_PROTOCOL"):
            self.assertIn(f"a.p4: {message}", errors)
        self.assertEqual((includes, examples), (0, 1))

    def test_catalogue_entries_match_library_files(self):
        cases = (
            ("", "missing catalogue entry for a.p4"),
            ("| `a.p4` |\n| `old.p4` |", "catalogue file does not exist: old.p4"),
            ("| `a.p4` |\n| `a.p4` |", "duplicate catalogue entry for a.p4"),
            ("| `a.p4` |\n2 P4 files", "file count 2, expected 1"),
            ("| `a.p4` |\n2 个 P4 文件", "file count 2, expected 1"),
            ('| `a.p4` |\n#include "missing.p4"', "missing include missing.p4"),
        )
        for readme, message in cases:
            with self.subTest(message=message):
                errors, _, _ = self.references({"a.p4": guarded("a.p4")}, readme)
                self.assertIn(f"README.md: {message}", errors)

    def test_padded_catalogue_entries_are_accepted(self):
        errors, _, _ = self.references({"a.p4": guarded("a.p4")},
                                      "| Filename | Name |\n| `a.p4`       | Test |\n")
        self.assertEqual(errors, [])

    def test_include_guards_are_required_and_consistent(self):
        for source in (DEFINITIONS, "#ifndef A_P4\n#define B_P4\n#endif\n",
                       "// #ifndef A_P4\n// #define A_P4\n"):
            with self.subTest(source=source):
                errors, _, _ = self.references({"a.p4": source})
                self.assertIn("a.p4: missing or inconsistent include guard", errors)

    def test_include_guards_are_unique(self):
        errors, _, _ = self.references({"a.p4": guarded("a.p4"),
                                        "b.p4": guarded("a.p4")})
        self.assertIn("b.p4: include guard also used by a.p4", errors)

    def test_includes_stay_within_the_library(self):
        for include in ("missing.p4", "../outside.p4", "nested/b.p4"):
            with self.subTest(include=include):
                sources = {"a.p4": guarded("a.p4", f'#include "{include}"')}
                root = self.library(sources)
                target = root / include
                target.parent.mkdir(exist_ok=True)
                target.write_text(guarded("b.p4"), encoding="utf-8")
                if include == "missing.p4":
                    target.unlink()
                errors, _, _ = checker.check_references(root, sources)
                self.assertIn(f"a.p4: missing library include {include}", errors)

    def test_include_cycles_are_reported(self):
        cases = (
            ({"a.p4": guarded("a.p4", '#include "a.p4"')}, "a.p4 -> a.p4"),
            ({"a.p4": guarded("a.p4", '#include "b.p4"'),
              "b.p4": guarded("b.p4", '#include "a.p4"')},
             "a.p4 -> b.p4 -> a.p4"),
        )
        for sources, cycle in cases:
            with self.subTest(cycle=cycle):
                errors, _, _ = self.references(sources)
                self.assertIn(f"include cycle: {cycle}", errors)

    def test_unknown_enum_members_are_reported(self):
        body = DEFINITIONS + EXAMPLE.replace("TestKind.DATA", "TestKind.MISSING")
        errors, _, _ = self.references({"a.p4": guarded("a.p4", body)})
        self.assertEqual(errors, ["a.p4: unknown example enum member TestKind.MISSING"])

    def test_constants_do_not_supply_parameter_types(self):
        body = "const bit<8> missing_type_t = 1;\n/*\n"
        body += "control Example(in missing_type_t value) { apply {} }\n*/"
        errors, _, _ = self.references({"a.p4": guarded("a.p4", body)})
        self.assertEqual(errors, ["a.p4: unknown example parameter type missing_type_t"])

    def test_local_symbols_and_caller_types_are_accepted(self):
        body = """
        /*
        header LocalHeader { varbit<64> payload; }
        enum bit<8> LocalKind { VALUE = 1 }
        control Example(in LocalKind KIND, in bit<8> FLAGS,
                        in LocalHeader[2] ITEMS, in headers hdr,
                        inout metadata meta, inout standard_metadata_t sm) {
            const bit<8> LOCAL_LIMIT = 4;
            bit<8> COUNTER;
            LocalKind MODE;
            apply {
                COUNTER = FLAGS + LOCAL_LIMIT;
                MODE = LocalKind.VALUE;
            }
        }
        */
        """
        self.assertEqual(self.references({"a.p4": guarded("a.p4", body)}), ([], 0, 1))

    def test_comments_and_strings_do_not_declare_symbols(self):
        declarations = (
            "// const bit<8> HIDDEN = 1;",
            "/* const bit<8> HIDDEN = 1; */",
            'const string DOC = "const bit<8> HIDDEN = 1;";',
        )
        example = "/*\ncontrol Example() { apply { value = HIDDEN; } }\n*/"
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                body = declaration + "\n" + example
                errors, _, _ = self.references({"a.p4": guarded("a.p4", body)})
                self.assertEqual(errors, ["a.p4: unknown example constant HIDDEN"])

    def test_strings_and_documentation_are_not_code_references(self):
        body = r'''
        // #include "missing.p4"
        /* #include "also_missing.p4" */
        const string DOC = "http://example.test/FAKE // header Ghost {}";
        /* Ordinary documentation mentioning UNKNOWN_CONSTANT. */
        /*
        @name("UNDECLARED_CONSTANT and an escaped quote: \" // text")
        control Example() { apply {} }
        */
        /*
        parser Other(packet_in pkt, out headers hdr) {
            state start { transition accept; }
        }
        */
        '''
        self.assertEqual(self.references({"a.p4": guarded("a.p4", body)}), ([], 0, 2))

    def test_reference_mode_needs_no_compilers(self):
        root = self.library({"a.p4": guarded("a.p4", DEFINITIONS + EXAMPLE)})
        result = self.run_check(root, "--references-only")
        self.assert_success(result)
        self.assertIn("1 files, 0 includes and 1 example blocks checked", result.stdout)
        self.assertNotIn("Compilation:", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_default_root_is_independent_of_working_directory(self):
        result = self.run_check(None, "--references-only")
        self.assert_success(result)
        self.assertIn(f"References: {len(list(REPOSITORY.glob('*.p4')))} files", result.stdout)

    def test_missing_compilers_are_reported(self):
        root = self.library({"a.p4": guarded("a.p4")})
        for available in (None, "p4test"):
            with self.subTest(available=available):
                if available:
                    self.install_compilers()
                    (self.bin / "p4c-bm2-ss").unlink()
                result = self.run_check(root)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                expected = "p4test, p4c-bm2-ss" if available is None else "p4c-bm2-ss"
                self.assertIn(f"Missing compiler(s): {expected}", result.stderr)

    def test_invalid_numeric_options_are_rejected(self):
        root = self.library({"a.p4": guarded("a.p4")})
        cases = {"--jobs": ("0", "-1", "1.5", "text"),
                 "--timeout": ("0", "-1", "nan", "inf", "-inf", "text")}
        for option, values in cases.items():
            for value in values:
                with self.subTest(option=option, value=value):
                    result = self.run_check(root, f"{option}={value}")
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(f"argument {option}:", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_empty_library_is_reported(self):
        result = self.run_check(self.library({}), "--references-only")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no P4 files", result.stderr)

    def test_missing_or_non_utf8_inputs_are_reported(self):
        for name, contents in (("README.md", None), ("README.md", b"\xff"),
                               ("a.p4", b"\xff")):
            with self.subTest(name=name, contents=contents):
                root = self.library({"a.p4": guarded("a.p4")})
                if contents is None:
                    (root / name).unlink()
                else:
                    (root / name).write_bytes(contents)
                result = self.run_check(root, "--references-only")
                self.assertEqual(result.returncode, 1)
                self.assertIn("Reference check failed:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_reference_errors_stop_compilation(self):
        self.install_compilers()
        root = self.library({"a.p4": DEFINITIONS})
        result = self.run_check(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or inconsistent include guard", result.stderr)
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_compilers_receive_individual_and_combined_sources(self):
        self.install_compilers()
        sources = {"a.p4": guarded("a.p4", DEFINITIONS), "b.p4": guarded("b.p4")}
        root = self.library(sources)
        result = self.run_check(root, "--jobs", "2")
        self.assert_success(result)
        self.assertIn("Compilation: 10/10 checks passed", result.stdout)
        calls = self.compiler_calls()
        self.assertEqual(len(calls), 10)
        for compiler in ("p4test", "p4c-bm2-ss"):
            selected = [call for call in calls if call["compiler"] == compiler]
            includes = [call["includes"] for call in selected]
            for expected in (["a.p4"], ["b.p4"], ["a.p4", "b.p4"], ["b.p4", "a.p4"]):
                self.assertEqual(includes.count(expected), 1)
            repeated = [names for names in includes if len(names) == 6]
            self.assertEqual(len(repeated), 1)
            for name in sources:
                self.assertEqual(repeated[0].count(name), 3)
        for call in calls:
            for name, source in call["sources"].items():
                self.assertEqual(source, sources[name])
            self.assertNotEqual(Path(call["cwd"]), root)
            self.assertFalse(Path(call["cwd"]).exists())
            args = call["args"]
            self.assertEqual(args[args.index("--std") + 1], "p4-16")
            self.assertIn("--Werror", args)
            self.assertFalse(Path(args[args.index("-I") + 1]).is_absolute())
            self.assertFalse(Path(next(arg for arg in args if arg.endswith(".p4"))).is_absolute())
        self.assertEqual(list(self.builds.iterdir()), [])
        self.assertEqual(sorted(path.name for path in root.iterdir()),
                         ["README.md", "a.p4", "b.p4"])

    def test_compiler_failures_include_output_and_clean_up(self):
        self.install_compilers()
        self.environment["HEADER_CHECK_TEST_MODE"] = "failure"
        result = self.run_check(self.library({"a.p4": guarded("a.p4")}), "--jobs", "2")
        self.assertEqual(result.returncode, 1)
        for message in ("single-a (p4test): exit 17", "compiler output", "compiler diagnostic"):
            self.assertIn(message, result.stderr)
        self.assertEqual(len(self.compiler_calls()), 8)
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_compiler_timeouts_are_reported_and_clean_up(self):
        self.install_compilers()
        self.environment["HEADER_CHECK_TEST_MODE"] = "timeout"
        result = self.run_check(self.library({"a.p4": guarded("a.p4")}),
                                "--jobs", "2", "--timeout", "0.2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("exceeded 0.2 seconds", result.stderr)
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_compiler_startup_errors_are_reported_and_clean_up(self):
        self.install_compilers()
        (self.bin / "p4test").write_text("invalid executable\n", encoding="utf-8")
        result = self.run_check(self.library({"a.p4": guarded("a.p4")}))
        self.assertEqual(result.returncode, 1)
        self.assertIn("single-a (p4test):", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(list(self.builds.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
