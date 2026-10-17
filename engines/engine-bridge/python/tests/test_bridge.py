"""The Python bridge, exercised from Python.

These run against the built wheel, not against a source checkout, because the
question P11.1.01 asks is whether `import pwdcrack` works for someone who
installed it. A test that imports the extension from a cargo target directory
proves something weaker.

Run by scripts/test-python-bridge.sh, which builds the wheel and installs it
into a throwaway prefix before invoking this.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import tempfile
import unittest

import pwdcrack

# MD5("pwdcrack-reference-candidate"). Computed here rather than copied, so a
# change to the hash implementation cannot quietly make the expectation wrong.
PLAINTEXT = "pwdcrack-reference-candidate"
TARGET = hashlib.md5(PLAINTEXT.encode()).hexdigest()

OTHER = "abcdefghijklmnopqrstuvwxyz0123456789"


class TestPackage(unittest.TestCase):
    """The package imports and advertises itself correctly."""

    def test_version_is_the_wrapped_librarys_version(self):
        # Was 0.1.0, the bridge crate's own version, while the library it wraps
        # is 1.2.0.
        self.assertEqual(pwdcrack.version(), pwdcrack.__version__)
        self.assertRegex(pwdcrack.__version__, r"^\d+\.\d+\.\d+")

    def test_py_typed_marker_ships(self):
        # Without this marker a type checker treats the package as untyped and
        # the annotations are decoration.
        marker = pathlib.Path(pwdcrack.__file__).parent / "py.typed"
        self.assertTrue(marker.exists(), "py.typed is missing from the wheel")

    def test_every_advertised_name_exists(self):
        for name in pwdcrack.__all__:
            self.assertTrue(hasattr(pwdcrack, name), f"{name} is exported but missing")


class TestCrackerTypes(unittest.TestCase):
    """The pyclass types mirror the Rust API."""

    def setUp(self):
        self.c = pwdcrack.Cracker()

    def test_a_fresh_cracker_is_empty(self):
        self.assertEqual(len(self.c), 0)
        self.assertEqual(self.c.target_count, 0)
        self.assertEqual(self.c.found, 0)

    def test_load_text_and_detect(self):
        self.assertEqual(self.c.load_text(TARGET + "\n"), 1)
        self.assertEqual(self.c.target_count, 1)
        self.assertEqual(len(self.c), 1)
        # The name comes from the cracker that recognised it, not a lookup table.
        self.assertRegex(self.c.detect(TARGET), r"(?i)md5")
        self.assertIsNone(self.c.detect("not a hash at all"))

    def test_targets_are_reported(self):
        self.c.load_text(TARGET + "\n")
        targets = self.c.targets
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].raw, TARGET)
        self.assertIsNone(targets[0].username)
        self.assertIn("md5", targets[0].hash_type.lower())

    def test_a_username_line_is_recognised(self):
        alice = hashlib.md5(b"alice-password").hexdigest()
        self.assertEqual(self.c.load_text(f"alice:{alice}\n"), 1)
        self.assertEqual(self.c.targets[0].username, "alice")

    def test_verify_has_three_answers(self):
        # 1, 0, and a raised exception. Collapsing the third into the second is
        # how a cracker reports a recovery that did not happen.
        self.assertTrue(self.c.verify(TARGET, PLAINTEXT))
        self.assertFalse(self.c.verify(TARGET, OTHER))
        with self.assertRaises(ValueError):
            self.c.verify("not a hash at all", PLAINTEXT)

    def test_verify_does_not_truncate(self):
        # The previous Node binding read into a 256 byte buffer, so a longer
        # password was silently answered about a truncated one.
        long_plaintext = "a" * 1000
        target = hashlib.md5(long_plaintext.encode()).hexdigest()
        self.assertTrue(self.c.verify(target, long_plaintext))
        self.assertFalse(self.c.verify(target, long_plaintext[:-1] + "b"))

    def test_rate_is_none_before_an_attack(self):
        self.assertIsNone(self.c.hashes_per_second)
        self.assertEqual(self.c.last_tested, 0)

    def test_engine_info_is_measured(self):
        info = self.c.engine_info()
        self.assertTrue(info.available)
        self.assertEqual(info.name, "cpu-scalar")
        # CpuEngine::new benchmarks itself, so this must be a number rather than
        # None.
        self.assertIsNotNone(info.hashes_per_second)
        self.assertGreater(info.hashes_per_second, 0.0)

    def test_an_attack_with_nothing_loaded_raises(self):
        with self.assertRaises(RuntimeError):
            self.c.attack_dictionary("/nonexistent/words.txt")


class TestAttacks(unittest.TestCase):
    """Real cracking through the Python surface."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.wordlist = os.path.join(self.dir, "words.txt")
        with open(self.wordlist, "w", encoding="utf-8") as handle:
            handle.write(OTHER + "\n")
            handle.write(PLAINTEXT + "\n")
        self.c = pwdcrack.Cracker()
        self.c.load_text(TARGET + "\n")

    def test_a_dictionary_attack_cracks(self):
        cracked = self.c.attack_dictionary(self.wordlist)
        self.assertEqual(cracked, 1)
        self.assertEqual(self.c.found, 1)
        # Two candidates in the file, both tested.
        self.assertEqual(self.c.last_tested, 2)

        result = self.c.results[0]
        self.assertIsInstance(result, pwdcrack.CrackedHash)
        self.assertEqual(result.hash, TARGET)
        self.assertEqual(result.password, PLAINTEXT)
        self.assertIn("md5", result.hash_type.lower())
        # The pair must actually be a match, not two agreeing implementations.
        self.assertEqual(hashlib.md5(result.password.encode()).hexdigest(), result.hash)

    def test_the_rate_is_measured(self):
        self.c.attack_dictionary(self.wordlist)
        rate = self.c.hashes_per_second
        self.assertIsNotNone(rate, "a finished attack must have a measurable rate")
        self.assertGreater(rate, 0.0)
        self.assertGreater(self.c.last_duration_secs, 0.0)

    def test_result_index_out_of_range_raises(self):
        self.c.attack_dictionary(self.wordlist)
        with self.assertRaises(IndexError):
            self.c.result(999)

    def test_a_bruteforce_attack_cracks(self):
        # A mask of literals, so the keyspace is exactly the plaintext.
        cracked = self.c.attack_bruteforce(PLAINTEXT)
        self.assertEqual(cracked, 1)
        self.assertEqual(self.c.results[0].password, PLAINTEXT)

    def test_two_crackers_do_not_share_state(self):
        # The module level functions share one process wide engine; the class
        # does not. That is the reason the class exists.
        other = pwdcrack.Cracker()
        self.assertEqual(other.target_count, 0)
        self.c.attack_dictionary(self.wordlist)
        self.assertEqual(self.c.found, 1)
        self.assertEqual(other.found, 0, "a second Cracker must not see the first's results")

    def test_a_second_attack_still_works(self):
        # The first version of this bridge took the targets out of the Cracker to
        # group them by cracker type and never put them back. The second attack
        # then found an empty list and reported zero cracks with success, which
        # reads as "searched everything and found nothing".
        first = self.c.attack_dictionary(self.wordlist)
        self.assertEqual(first, 1)
        second = self.c.attack_dictionary(self.wordlist)
        self.assertEqual(second, 1, "a second attack must still find the hash")
        self.assertEqual(self.c.target_count, 1, "the targets survived the first run")

    def test_attacks_run_twice_over_different_masks(self):
        self.assertEqual(self.c.attack_bruteforce(PLAINTEXT), 1)
        self.assertEqual(self.c.attack_dictionary(self.wordlist), 1)
        self.assertEqual(self.c.target_count, 1)

    def test_clear_resets(self):
        self.c.attack_dictionary(self.wordlist)
        self.c.clear()
        self.assertEqual(self.c.target_count, 0)
        self.assertEqual(self.c.found, 0)
        self.assertIsNone(self.c.hashes_per_second)


class TestFreeFunctions(unittest.TestCase):
    """The pre-existing module level surface still works."""

    def test_detect_and_verify(self):
        self.assertIsNotNone(pwdcrack.detect(TARGET))
        self.assertTrue(pwdcrack.verify_one(TARGET, PLAINTEXT))
        self.assertFalse(pwdcrack.verify_one(TARGET, OTHER))

    def test_a_dictionary_run_through_the_free_functions(self):
        loaded = pwdcrack.load_buffer((TARGET + "\n").encode())
        self.assertEqual(loaded, 1)
        self.assertEqual(pwdcrack.verify_batch(PLAINTEXT), [TARGET])


if __name__ == "__main__":
    unittest.main(verbosity=2)