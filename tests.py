import unittest
from main import PasswordGenerator, PasswordTooShortError
import string


class TestPasswordGenerator(unittest.TestCase):
    pypass = PasswordGenerator()

    def generate_and_print_password(self, length: int, symbols: bool, mixed_case: bool, banned: list[str]):
        password = self.pypass.generate_password(
            length, symbols, mixed_case, banned)
        if password:
            print(
                f"🔒 {password}" if password else "❗ A secure password could not be generated.")
        return password

    def test_too_short(self):
        self.assertRaises(
            PasswordTooShortError, self.generate_and_print_password, 5, False, False, [])

    def test_mixed_case_symbols(self):
        password = self.generate_and_print_password(10, True, True, [])

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

    def test_mixed_case_not_symbols(self):
        password = self.generate_and_print_password(10, False, True, [])

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        symbols = set(string.punctuation)
        self.assertTrue(not any(char in symbols for char in password),
                        "Password should not contain symbols")

    def test_not_mixed_case_not_symbols(self):
        password = self.generate_and_print_password(10, False, False, [])

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        symbols = set(string.punctuation)
        self.assertTrue(not any(char in symbols for char in password),
                        "Password should not contain symbols")

        self.assertTrue(password.islower() or password.isupper(),
                        "Password should not be mixed case")

    def test_mixed_case_symbols_banned(self):
        banned_characters = ["a", "e", "i", "o", "u"]
        password = self.generate_and_print_password(
            10, True, True, banned_characters)

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        self.assertTrue(not any(char in banned_characters for char in password),
                        "Password should not contain characters from the banned list")


if __name__ == '__main__':
    unittest.main(verbosity=2)
