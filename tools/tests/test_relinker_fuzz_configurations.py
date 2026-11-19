import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import relinker_fuzz_seeds


class RelinkerFuzzConfigurationsTests(unittest.TestCase):
    def test_opt_in_corpus_covers_every_configuration_and_preserves_default_seeds(self):
        expected = {(target, intel, validation) for target in range(3) for intel in (False, True) for validation in range(3)}
        images = dict(relinker_fuzz_seeds.images())
        self.assertTrue(images)
        self.assertEqual(relinker_fuzz_seeds.SELECTORS, (0, 1, 2, 4))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for all_configurations in (False, True):
                output = root / ("all" if all_configurations else "default")
                command = [sys.executable, str(Path(relinker_fuzz_seeds.__file__)), str(output)]
                result = subprocess.run(command + (["--all-configurations"] if all_configurations else []),
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                count = 18 if all_configurations else 4
                self.assertEqual(len(list(output.iterdir())), len(images) * count)
                for name, image in images.items():
                    configurations = set()
                    selectors = set()
                    for seed in output.glob(name + "-*"):
                        data = seed.read_bytes()
                        selector = data[0]
                        self.assertEqual(seed.name, name + "-" + str(selector))
                        self.assertEqual(data[1:], image)
                        selectors.add(selector)
                        configurations.add((selector % 3, bool(selector & 4), (selector >> 3) % 3))
                    if all_configurations:
                        self.assertEqual(configurations, expected)
                    else:
                        self.assertEqual(selectors, {0, 1, 2, 4})


    def test_extended_options_add_one_seed_per_target_and_option_after_the_default_seeds(self):
        images = dict(relinker_fuzz_seeds.images())
        self.assertTrue(images)
        expected = {(target, 1 << bit) for target in range(3) for bit in range(relinker_fuzz_seeds.EXTENDED_OPTION_BITS)}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "extended"
            result = subprocess.run([sys.executable, str(Path(relinker_fuzz_seeds.__file__)), str(output), "--extended-options"],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(output.iterdir())), len(images) * (4 + len(expected)))
            for name, image in images.items():
                legacy = set()
                extended = set()
                for seed in output.glob(name + "-*"):
                    data = seed.read_bytes()
                    selector = data[0]
                    if (selector >> 3) < 3:
                        self.assertEqual(seed.name, name + "-" + str(selector))
                        self.assertEqual(data[1:], image)
                        legacy.add(selector)
                        continue
                    self.assertEqual(selector, relinker_fuzz_seeds.EXTENDED_SELECTOR | selector % 3)
                    options = int.from_bytes(data[1:3], "little")
                    self.assertEqual(seed.name, f"{name}-x{selector % 3}-{options:04x}")
                    self.assertEqual(data[3:], image)
                    extended.add((selector % 3, options))
                self.assertEqual(legacy, {0, 1, 2, 4})
                self.assertEqual(extended, expected)

    def test_guest_module_seeds_hold_an_executable_and_named_modules(self):
        cases = list(relinker_fuzz_seeds.guest_modules())
        self.assertIn("test_guest_gnu_hash-provider", [name for name, _, _ in cases])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "guest"
            result = subprocess.run([sys.executable, str(Path(relinker_fuzz_seeds.__file__)), str(output), "--guest-modules"],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(output.iterdir())), len(cases) * len(relinker_fuzz_seeds.SELECTORS))
            for name, executable, modules in cases:
                for selector in relinker_fuzz_seeds.SELECTORS:
                    data = (output / f"{name}-{selector}").read_bytes()
                    self.assertEqual(data[0], selector)
                    records = []
                    rest = data[1:]
                    while rest:
                        length = int.from_bytes(rest[:4], "little")
                        records.append(rest[4:4 + length])
                        rest = rest[4 + length:]
                    self.assertEqual(records[0], executable)
                    self.assertEqual(records[1:], [part for file, image in modules for part in (file.encode(), image)])

    def test_all_configurations_reports_invalid_output_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing.bin"
            existing.write_bytes(b"preserve output")
            for output in (existing, existing / "child"):
                with self.subTest(output=output):
                    result = subprocess.run([sys.executable, relinker_fuzz_seeds.__file__, str(output), "--all-configurations"],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(existing.read_bytes(), b"preserve output")


if __name__ == "__main__":
    unittest.main()
