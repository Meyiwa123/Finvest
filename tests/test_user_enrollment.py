from src.finvest import PasswordFile, UserEnrollment

def test_user_enrollment():
    # Initialize Password File
    password_file = PasswordFile()
    user_enrollment = UserEnrollment(password_file)

    # Input user credentials
    user_id = input("Enter user ID: ")
    password = input("Enter password: ")
    role = input("Enter role: ")

    # Enroll user
    if user_enrollment.enroll_user(user_id, password, role):
        print("User enrolled successfully!")
    else:
        print("User enrollment failed!")


def test_password_checker():
    # Initialize Password File
    password_file = PasswordFile()
    user_enrollment = UserEnrollment(password_file)
    # passwords to test
    test_passwords = [
        'Password1',
        'Abc123',
        'Qwerty123',
        'abc123!',
        'ABC123!',
        'AbCdEfGhI!',
        'AbCdEfGhI123',
        'user123!',
        'Qaz123wsx'
    ]
    # test weak passwords
    for password in test_passwords:
        assert user_enrollment.is_password_valid(password, "test") == False

    print("Test passed.")


if __name__ == '__main__':
    test_user_enrollment()
    test_password_checker()
