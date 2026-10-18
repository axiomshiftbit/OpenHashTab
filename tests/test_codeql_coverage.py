import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    'codeql_coverage', pathlib.Path(__file__).resolve().parents[1] / 'automation/Check-CodeQLCoverage.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def row(path, completed=1, crashed=0, functions=1, parsed=1):
    return dict(path=path, completed=completed, crashed=crashed, functions=functions, parsed=parsed)


class ExtractionCoverage(unittest.TestCase):
    def setUp(self):
        self.header = row('OpenHashTab/OpenHashTab/json.h', completed=0)

    def test_complete_database(self):
        self.assertEqual(gate.check([row('a.cpp'), self.header], {'a.cpp'}), 0)

    def test_untraced_source_fails(self):
        self.assertEqual(gate.check([row('a.cpp'), self.header], {'a.cpp', 'b.cpp'}), 1)

    def test_crash_even_if_another_architecture_succeeded(self):
        self.assertEqual(gate.check([row('a.cpp', completed=2, crashed=1), self.header], {'a.cpp'}), 1)

    def test_traced_but_not_extracted_source_fails(self):
        self.assertEqual(gate.check([row('a.cpp', completed=0), self.header], {'a.cpp'}), 1)

    def test_normal_exit_without_source_entities_fails(self):
        self.assertEqual(gate.check([row('a.cpp', parsed=0), self.header], {'a.cpp'}), 1)

    def test_dependency_crash_fails(self):
        self.assertEqual(gate.check([row('a.cpp'), row('vendor/b.c', crashed=1), self.header], {'a.cpp'}), 1)

    def test_missing_json_functions_fail(self):
        for header in ([], [row(self.header['path'], completed=0, functions=0)]):
            with self.subTest(header=header):
                self.assertEqual(gate.check([row('a.cpp'), *header], {'a.cpp'}), 1)

    def test_included_sphlib_implementation_requires_extracted_functions(self):
        name = 'Algorithms/extended/sphlib/md_helper.c'
        for functions, expected in ((1, 0), (0, 1)):
            with self.subTest(functions=functions):
                self.assertEqual(gate.check([row(name, completed=0, functions=functions), self.header], {name}), expected)

    def test_invalid_input_fails(self):
        for rows, sources in (([], set()), ([row('a'), row('a')], {'a'}), ([row('a', crashed=-1)], {'a'})):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                gate.check(rows, sources)
