"""
Write a Python function that returns a random password. 
- ✅ Input params should be length: int, symbols: bool, mixed_case: bool, and 
  banned: list[str]
- ✅ The password should never return any characters in the banned list. The 
  other params are self-explanatory.
- ✅ We want to make sure users are staying safe, so if length is less than 10 
  characters, raise a custom exception (write the exception class yourself). 
  This exception should have a readable and descriptive name and docstring.
- ✅ Make sure the docstrings follow PEP 257.
- ✅ the tool must never return the same password twice, however unlikely that 
  may be, so include a mechanism to ensure that's not possible.
- ✅ Bonus point if you solve it using 🌟 recursion 🌟
"""

import random
import string
import hashlib
import sys


class PasswordLengthError(Exception):
    """
    Exception raised if a user inputs a password length that is too short or 
    too long.
    """

    def __init__(self, message):
        """
        Initializes the PasswordLengthError exception with an error message.

        Args:
            message (str): An explanation of the error.
        """

        super().__init__(message)


class PasswordGenerator():
    def __init__(self):
        self.min_password_length = 10
        self.max_password_length = 500

        print(r"""
                __________        __________                       
                \______   \___.__.\______   \_____    ______ ______
                |     ___<   |  | |     ___/\__  \  /  ___//  ___/
                |    |    \___  | |    |     / __ \_\___ \ \___ \ 
                |____|    / ____| |____|    (____  /____  >____  >
                """)
        print(
            "       ✨ Welcome to PyPass, your friendly neighborhood password "
            "generator. ✨\n")

    def get_user_inputs(self):
        """
        Prompts the user for various password-related inputs and returns these
        in a dictionary.

        Internally runs `self.get_length_input`, `self.get_yes_no_input`, and 
        `self.get_banned_input`.
        """

        length = self.get_length_input()
        symbols = self.get_yes_no_input(
            "\nAllow symbols? [Y]es or Enter / [N]o: "
        )
        mixed_case = self.get_yes_no_input(
            "\nAllow mixed case? [Y]es or Enter / [N]o: "
        )
        banned = self.get_banned_input(symbols)

        return {
            "length": length,
            "symbols": symbols,
            "mixed_case": mixed_case,
            "banned": banned
        }

    def get_yes_no_input(self, prompt_message: str):
        """
        Asks the user a yes/no question and returns True for yes, False for no.
        """

        user_input = input(prompt_message)
        while user_input != "" and user_input.lower() not in ["y", "n"]:
            print(
                "Please type Y or N (case-insensitive). Press enter for the "
                "default (Y)."
            )
            user_input = input(prompt_message)
        else:
            is_yes = user_input == "" or user_input.lower() == "y"
        return is_yes

    def get_length_input(self):
        """
        Prompts the user to input an integer length, and returns it.

        If the user enters certain numbers, prints different fun text to the
        console.

        Raises:
            PasswordLengthError -- If the user inputs a password length that 
                                   is less than the minimum or more than the
                                   maximum.
        """

        try:
            prompt_message = "\nPassword Length: "
            length_input = input(prompt_message)
            while not length_input.isdigit():
                print("Please enter a valid integer.")
                length_input = input(prompt_message)
            else:
                length = int(length_input)

            match length:
                case _ if length < self.min_password_length:
                    raise PasswordLengthError(
                        "🔴 Your password must be at least "
                        f"{self.min_password_length} characters long!"
                    )
                case _ if length > 500:
                    raise PasswordLengthError(
                        "🔴 Your password must not be more than "
                        f"{self.max_password_length} characters long!"
                    )
                case _ if length >= 100:
                    print("You'd better write this one down.")
                case 42:
                    print("I can't give you answer to the Ultimate Question "
                          "of Life, the Universe, and Everything, but I can "
                          "give you a password."
                          )
            return length

        except PasswordLengthError as e:
            new_password_length = (
                self.min_password_length if length < self.min_password_length
                else self.max_password_length
            )
            password_change_explanation = "To keep you safe" if length < \
                self.min_password_length else "To keep things less dramatic"
            print(e,
                  f"\n🔐 {password_change_explanation}, your password length "
                  f"has been set to {new_password_length}.")
            return new_password_length

    def get_banned_input(self, symbols: bool):
        """
        Prompts the user to input an optional string of banned characters, 
        and returns this as a list.

        Validates the input string to ensure it is not banning ALL possible 
        characters, including uppercase, lowercase, and digits. If it includes
        all of these, prompts the user to input a different string of banned 
        characters.

        Args:
            symbols (bool) -- Whether or not the user chose to allow symbols.
        """

        prompt_message = (
            "\nYou may enter characters to exclude from the "
            "password. Please enter them as a continuous string; every "
            "character in this string will be excluded. This string is "
            "case-sensitive.\nBanned characters: "
        )

        banned_input = input(prompt_message)
        all_possible_characters = string.digits + string.ascii_letters
        if symbols:
            all_possible_characters += string.punctuation
        while set(all_possible_characters).issubset(set(banned_input)):
            print(
                "\n❗ Whoa there! You can't ban EVERYTHING. What are you "
                "trying to pull?"
            )
            banned_input = input(prompt_message)
        else:
            banned = set(banned_input)
        return banned

    def hash_password(self, password: str):
        """Hashes a password and returns it."""
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password

    def store_password(self, password: str):
        """
        Appends the password to passwords.txt, and returns nothing.

        Internally runs `self.hash_password` to hash `password` before 
        appending it to passwords.txt.

        If passwords.txt cannot be found, creates it, and appends the hashed 
        password to it.

        Args:
            password (str) -- The password that needs to be stored.

        Raises:
            PermissionError -- If the user does not have permission to write 
                               to passwords.txt.
            IsADirectoryError -- If passwords.txt is a directory, not a file.
            OSError -- If a system-related error occurs, such as "disk full".
            IOError -- An alias of OSError.
        """

        hashed_password = self.hash_password(password)
        try:
            with open('passwords.txt', 'a') as file:
                file.write(hashed_password + '\n')
        except FileNotFoundError:
            with open('passwords.txt', 'w') as file:
                file.write(hashed_password + '\n')
        except (
            PermissionError,
            IsADirectoryError,
            OSError,
            IOError
        ) as e:
            raise e

    def check_password_uniqueness(self, password: str):
        """
        Returns True if the password is unique, and False otherwise.

        Internally runs `self.hash_password`, and then checks if this hashed 
        password exists in passwords.txt. If so, the password is not unique, 
        and False is returned. Otherwise, True is returned.

        If passwords.txt cannot be found, creates it, and returns True.

        Args:
            password (str) -- The password whose uniqueness to check.

        Raises:
            PermissionError -- If the user does not have permission to write 
                               to passwords.txt.
            IsADirectoryError -- If passwords.txt is a directory, not a file.
            OSError -- If a system-related error occurs, such as "disk full".
            IOError -- An alias of OSError.
        """

        hashed_password = self.hash_password(password)
        try:
            with open('passwords.txt', 'r') as file:
                file_readable = file.read()
                return hashed_password not in file_readable
        except FileNotFoundError:
            file = open('passwords.txt', 'x')
            file.close()
            return True
        except (
            PermissionError,
            IsADirectoryError,
            OSError,
            IOError
        ) as e:
            raise e

    def recursively_create_password(
            self,
            unique_password_attempts: int,
            length: int,
            allowed_characters: str,
            password: str
    ):
        """
        Recursively runs until the length of the password matches `length`,
        and returns the password.

        Args:
            unique_password_attempts (int) -- Number of attempts to generate a
                                              unique password.
            length (int) -- The length of the password.
            allowed_characters (str) -- Characters allowed in the password.
            password (str) -- The running password as it is being generated.

        Raises:
            RuntimeError -- If the number of attempts to generate a unique 
            password is greater than or equal to 10.
        """

        if len(password) < length:
            password += random.choice(allowed_characters)
            return self.recursively_create_password(
                unique_password_attempts,
                length,
                allowed_characters,
                password
            )
        else:
            try:
                if self.check_password_uniqueness(password):
                    self.store_password(password)
                    return password
                else:
                    unique_password_attempts += 1
                    if unique_password_attempts >= 10:
                        raise RuntimeError(
                            f"Failed to generate a unique password after "
                            f"{unique_password_attempts} attempts."
                        )
                    else:
                        return self.recursively_create_password(
                            unique_password_attempts,
                            length,
                            allowed_characters,
                            ""
                        )
            except (
                PermissionError,
                IsADirectoryError,
                OSError,
                IOError
            ) as e:
                print(
                    "There was an error verifying if this password is "
                    "unique. Are you sure you have permission to read "
                    "or write to passwords.txt? Does it even exist? "
                )
                print(
                    "Though I can't verify if it's unique or store it, "
                    "here's the password, anyway. "
                )
                return password

    def generate_password(
            self,
            length: int,
            symbols: bool,
            mixed_case: bool,
            banned: list[str]
    ):
        """
        Return a password.

        The password will be `length` characters long. It will contain both 
        uppercase and lowercase characters if `mixed_case` is True, otherwise 
        the characters will be exclusively uppercase or lowercase, with a 50% 
        chance of either option, unless `banned` contains every uppercase or 
        every lowercase character and all digits. The password will not 
        contain any characters in `banned`.

        Internally runs `self.recursively_create_password` to create the 
        password.

        Internally runs `self.check_password_uniqueness` and 
        `self.store_password` to verify that the password is unique, and then 
        storing it in passwords.txt if so.

        Args:
            length (int) -- The length of the password.
            symbols (bool) -- Whether or not the password can contain symbols.
            mixed_case (bool) -- Whether or not the password will contain 
                                 mixed case characters.
            banned (str) -- A list of characters to exclude from the password.

        Raises:
            PasswordLengthError -- If the user selects a password length 
                                   less than the minimum or more than the 
                                   maximum.
            RuntimeError -- If the program fails to generate a unique password
                            after 10 attempts, or the user bans all characters.
        """

        try:
            if length < self.min_password_length:
                raise PasswordLengthError(
                    "🔴 Your password must be at least "
                    f"{self.min_password_length} characters long!"
                )
            elif length > self.max_password_length:
                raise PasswordLengthError(
                    "🔴 Your password must not be more than "
                    f"{self.max_password_length} characters long!"
                )

            characters = string.digits
            if mixed_case:
                characters += string.ascii_letters
            else:
                if set(string.ascii_lowercase).issubset(set(banned)) and \
                        "".join(banned) == "".join(banned).lower():
                    password_case = 0
                elif set(string.ascii_uppercase).issubset(set(banned)) and \
                        "".join(banned) == "".join(banned).upper():
                    password_case = 1
                else:
                    password_case = random.choice([0, 1])
                characters += string.ascii_lowercase if password_case == 1 \
                    else string.ascii_uppercase
            if symbols:
                characters += string.punctuation

            characters = "".join(
                [char for char in characters if char not in banned])

            if not characters:
                raise RuntimeError(
                    "You banned every character! Think you're pretty slick, "
                    "huh? Try again."
                )

            generated_password = self.recursively_create_password(
                0, length, characters, "")
            return generated_password

        except (PasswordLengthError, RuntimeError) as e:
            raise e

    def begin_program(self):
        """
        Runs `self.run_password_generator` if the user wants to generate a 
        password.

        Prompts the user to select if they'd like to generate a new password 
        by internally running `self.get_yes_no_input`. Internally runs 
        `self.run_password_generator` if they say yes. Otherwise, prints a fun 
        text response to the user.
        """

        try:
            user_response_is_yes = self.get_yes_no_input(
                "Would you like to generate a new password? [Y]es or Enter / "
                "[N]o: "
            )
            if user_response_is_yes:
                self.run_password_generator()
            else:
                print("\n❓ Then why did you start this program?\n")

        except KeyboardInterrupt:
            print("\nYou could have just said no. Goodbye.")
            sys.exit(0)

    def run_password_generator(self):
        """Runs the password generator, and returns nothing.

        First, user inputs are gathered using `self.get_user_inputs`.
        Then, a summary of user inputs is printed, and a password is generated
        and printed using `self.generate_password`.
        Finally, `self.begin_program` runs, prompting the user to generate 
        another new password.
        """
        try:
            user_inputs = self.get_user_inputs()

            print(
                f"\nLength: {user_inputs['length']} "
                f"\nAllow symbols: {user_inputs['symbols']} "
                f"\nAllow mixed case: {user_inputs['mixed_case']} "
                f"\nBanned list: {', '.join(user_inputs['banned'])}\n"
            )
            print(
                "🔒",
                self.generate_password(
                    user_inputs["length"],
                    user_inputs["symbols"],
                    user_inputs["mixed_case"],
                    user_inputs["banned"]
                ),
                "\n"
            )

            self.begin_program()

        except KeyboardInterrupt:
            print(
                "\nI see you're no longer interested in being secure. Good "
                "luck with that!"
            )
            sys.exit(0)

        except PasswordLengthError:
            print("Looks like your password wasn't between "
                  f"{self.min_password_length} and {self.max_password_length}."
                  "Go ahead and try again.")

        except RuntimeError as e:
            print("I wasn't able to generate a unique password. Try again?")


if __name__ == '__main__':
    pypass = PasswordGenerator()
    pypass.begin_program()
