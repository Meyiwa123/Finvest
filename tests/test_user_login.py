from src.finvest import PasswordFile, UserEnrollment

def test_user_login():
    # Initialize Password File
    password_file = PasswordFile()
    user_enrollment = UserEnrollment(password_file)

    # Create/Ensure user exists
    user_id = "user1"
    password = "P@sswd9870l"
    role = "Client"
    user_enrollment.enroll_user(user_id, password, role)

    # Test invalid login
    assert user_enrollment.verify_user(user_id, "invalid") == False
    # Test login
    assert user_enrollment.verify_user(user_id, password) == True
    print("Test passed.")


if __name__ == '__main__':
    test_user_login()
