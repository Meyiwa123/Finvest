import secrets
from src.finvest import PasswordFile

def test_password_file():
    # Initialize Password File
    password_file = PasswordFile()
    # Test Case: Salt
    salt = secrets.token_hex(16)
    # Test Case: Hash Password
    hashed_password = password_file.hash_password("P@ssw0rd!123", salt)
    # Test Case: User already exists
    assert (password_file.get_record('testUser')
            ) == None, "Test Case Failed, user already exists"
    # Test Case: Add Record
    password_file.add_record("testUser", salt,
                             hashed_password, "Client")
    # Test Case: Get Record
    retrieved_record = password_file.get_record("testUser")
    # Assertion
    assert retrieved_record == {
        'user_id': 'testUser',
        'salt': salt,
        'hashed_password': hashed_password,
        'role': 'Client'
    }, f"Test Case Failed: {retrieved_record}"
    print("Test Case Passed")


if __name__ == '__main__':
    test_password_file()
