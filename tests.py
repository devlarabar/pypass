import unittest
from main import PasswordGenerator, PasswordLengthError
import string


class TestPasswordGenerator(unittest.TestCase):
    """
    Test cases for the PasswordGenerator class.

    Contains tests for the PasswordGenerator class to ensure passwords
    are correctly generated according to specified parameters, and that 
    errors are raised when expected (for example, if the password length
    is less than 10).
    """

    pypass = PasswordGenerator()

    def generate_and_print_password(
            self,
            length: int,
            symbols: bool,
            mixed_case: bool,
            banned: list[str]
    ):
        """
        Returns and prints a password (string) with the given parameters.

        Args:
            length (int) -- Length of the password.
            symbols (bool) -- Whether the password should include symbols.
            mixed_case (bool) -- Whether the password should include both
                                 uppercase and lowercase letters.
            banned (list[str]) -- Characters to be excluded from the password.
        """

        password = self.pypass.generate_password(
            length, symbols, mixed_case, banned)
        if password:
            print(f"🔒 {password}")
        return password

    def test_length_error(self):
        """
        Tests that PasswordLengthError is raised for passwords shorter 
        than the minimum, or longer than the maximum.
        """

        self.assertRaises(
            PasswordLengthError,
            self.generate_and_print_password,
            5,
            False,
            False,
            []
        )

        self.assertRaises(
            PasswordLengthError,
            self.generate_and_print_password,
            505,
            False,
            False,
            []
        )

    def test_mixed_case_symbols(self):
        """Tests that a password is generated with the correct length."""
        password = self.generate_and_print_password(50, True, True, [])

        self.assertEqual(len(password), 50,
                         "Password must be 50 characters long")

    def test_mixed_case_not_symbols(self):
        """
        Tests that a password of the correct length will be generated without 
        symbols when the user chooses not to include symbols.
        """

        password = self.generate_and_print_password(10, False, True, [])

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        symbols = set(string.punctuation)
        self.assertTrue(not any(char in symbols for char in password),
                        "Password should not contain symbols")

    def test_not_mixed_case_not_symbols(self):
        """
        Tests that a password of the correct length will be generated without 
        symbols or mixed casing.

        Tests that the password is generated without symbols and entirely
        uppercase or entirely lowercase characters when the user chooses
        not to include symbols or mixed casing.
        """

        password = self.generate_and_print_password(10, False, False, [])

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        symbols = set(string.punctuation)
        self.assertTrue(not any(char in symbols for char in password),
                        "Password should not contain symbols")

        self.assertTrue(password.islower() or password.isupper(),
                        "Password should not be mixed case")

    def test_mixed_case_symbols_banned(self):
        """
        Tests that a password will be generated with the right length and 
        without any of the characters in `banned_characters`.
        """

        banned_characters = ["a", "e", "i", "o", "u"]
        password = self.generate_and_print_password(
            10, True, True, banned_characters)

        self.assertEqual(len(password), 10,
                         "Password must be 10 characters long")

        self.assertTrue(not any(
            char in banned_characters for char in password
        ),
            (
            "Password should not contain characters from the "
            "banned list"
        ))

    def test_not_mixed_case_not_symbols_ban_uppercase(self):
        """
        Tests that a password is generated without symbols and in lowercase.

        Verifies that the generated password contains all lowercase 
        characters and no symbols, given the user chooses to exclude symbols,
        and given a list of characters to be excluded, which contains all 
        digits and uppercase characters.
        """

        banned_characters = list(string.ascii_uppercase + string.digits)
        password = self.generate_and_print_password(
            10, False, False, banned_characters)
        self.assertTrue(not any(char == char.upper() for char in password))

    def test_not_mixed_case_not_symbols_ban_lowercase(self):
        """
        Tests that a password is generated without symbols and in uppercase.

        Verifies that the generated password contains all uppercase 
        characters and no symbols, given the user chooses to exclude symbols,
        and given a list of characters to be excluded, which contains all 
        digits and lowercase characters.
        """

        banned_characters = list(string.ascii_lowercase + string.digits)
        password = self.generate_and_print_password(
            10, False, False, banned_characters)
        self.assertTrue(not any(char == char.lower() for char in password))

    def test_all_chars_banned(self):
        """
        Tests that a RuntimeError is raised if the user bans all characters.
        """

        self.assertRaises(
            RuntimeError,
            self.generate_and_print_password,
            10,
            False,
            False,
            list(string.ascii_letters + string.digits)
        )

        self.assertRaises(
            RuntimeError,
            self.generate_and_print_password,
            10,
            False,
            True,
            list(string.ascii_letters + string.digits)
        )

        self.assertRaises(
            RuntimeError,
            self.generate_and_print_password,
            10,
            True,
            False,
            list(string.ascii_letters + string.digits + string.punctuation)
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
