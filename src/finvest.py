import os
import secrets
import hashlib

class AccessControl:
    def __init__(self):
        self.acl = {}

    def add_role(self, role, permissions):
        self.acl[role] = permissions

    def check_permission(self, role, permission):
        if role in self.acl and permission in self.acl[role]:
            return True
        return False
    
    def get_permissions_for_role(self, role):
        return self.acl.get(role, [])

class PasswordFile:
    def __init__(self, file_name='passwd.txt'):
        current_directory = os.getcwd()
        self.file_path = os.path.join(current_directory, file_name)

    def hash_password(self, password, salt):
        """
        Hashes the password using SHA-256 and a salt.
        """
        hash_object = hashlib.sha256()
        hash_object.update((password + salt).encode('utf-8'))
        hashed_password = hash_object.hexdigest()
        return hashed_password

    def add_record(self, user_id, salt, hashed_password, role):
        """
        Adds a new record to the password file.
        """
        with open(self.file_path, 'a') as file:
            file.write(f"{user_id}:{salt}:{hashed_password}:{role}\n")

    def get_record(self, user_id):
        """
        Retrieves a record from the password file based on user ID.
        """
        with open(self.file_path, 'r') as file:
            for line in file:
                fields = line.strip().split(':')
                if fields[0] == user_id:
                    return {
                        'user_id': fields[0],
                        'salt': fields[1],
                        'hashed_password': fields[2],
                        'role': fields[3]
                    }
        return None

class UserEnrollment:
    def __init__(self, password_file, weak_password_file='weak_passd.txt'):
        self.password_file = password_file
        self.weak_password_file = weak_password_file
        self.common_weak_passwords = None
        self.load_weak_passwords()

    def is_password_valid(self, password, user_id):
        # Check password length
        if not (8 <= len(password) <= 12):
            return False

        # Check character types
        has_uppercase = any(char.isupper() for char in password)
        has_lowercase = any(char.islower() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special_char = any(char in '!@#$%?*' for char in password)

        if not (has_uppercase and has_lowercase and has_digit and has_special_char):
            return False

        # Check common weak passwords
        if password in self.common_weak_passwords:
            return False

        # Check for format matching user ID
        if password == user_id:
            return False

        return True
    
    def load_weak_passwords(self):
        try:
            with open(self.weak_password_file, 'r') as file:
                self.common_weak_passwords = set(file.read().splitlines())
        except FileNotFoundError:
            self.common_weak_passwords = set(["password"])

    def enroll_user(self, user_id, password, role):
        # Check if user ID is already enrolled
        if self.password_file.get_record(user_id):
            return False

        # Check if password is valid
        if not self.is_password_valid(password, user_id):
            return False

        # Hash password
        salt = secrets.token_hex(16)
        hashed_password = self.password_file.hash_password(password, salt)

        # Add record to password file
        self.password_file.add_record(user_id, salt, hashed_password, role)

        return True
    
class UserVerification:
    def __init__(self, password_file):
        self.password_file = password_file

    def verify_user(self, user_id, password):
        # Retrieve record from password file
        record = self.password_file.get_record(user_id)
        if record is None:
            return False

        # Hash password
        hashed_password = self.password_file.hash_password(password, record['salt'])

        # Verify password
        if hashed_password == record['hashed_password']:
            return True
        return False
    
class CommandLineUI:
    def __init__(self, password_file, user_enrollment, user_verification, access_control):
        self.logged_in = False
        self.username = None
        self.password = None
        self.access_control = access_control
        self.password_file = password_file
        self.user_enrollment = user_enrollment
        self.user_verification = user_verification

    def clear_console(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def clear_credentials(self):
        self.logged_in = False
        self.username = None
        self.password = None

    def run(self):
        while True:
            self.display_title()
            choice = input("Enter choice: ")
            if choice == "2":
                self.login()
                if self.logged_in:
                    self.display_user_info()
            elif choice == "1":
                self.enroll()
            elif choice == "0":
                print("Exiting the system. Goodbye!")
                break
            else:
                print("Invalid choice.")

            input("Press Enter to continue...")
            self.clear_credentials()
            self.clear_console()

    def display_title(self):
        print("Finvest Holdings")
        print("Client Holdings and Information System")
        print("--------------------------------------------------------")
        print("0. Exit")
        print("1. Enroll")
        print("2. Login")

    def display_user_info(self):
        record = self.password_file.get_record(self.username)
        if record:
            user_id = record['user_id']
            role = record['role']
            permissions = self.access_control.get_permissions_for_role(role)
            print("--------------------------------------------------------")
            print("User Information:")
            print(f"User ID: {user_id}")
            print(f"Role: {role}")
            print("Permissions:")
            for permission in permissions:
                print(f"  - {permission}")
        else:
            print("User not found.")

    def login(self):
        print("Please login to continue.")
        self.username = input("Username: ")
        self.password = input("Password: ")
        if self.user_verification.verify_user(self.username, self.password):
            print("Login successful.")
            self.logged_in = True
        else:
            print("Login failed.")

    def enroll(self):
        print("Please enroll to continue.")
        self.username = input("Username: ")
        self.password = input("Password: ")
        role = input("Role: ")
        if self.user_enrollment.enroll_user(self.username, self.password, role):
            print("Enrollment successful.")
        else:
            print("Enrollment failed.")

def main():
    # Initialize Password File
    password_file = PasswordFile()
    # Initialize Access Control
    access_control = AccessControl()
    # Initialize User Enrollment
    user_enrollment = UserEnrollment(password_file)
    # Initialize User Verification
    user_verification = UserVerification(password_file)
    
    # Add roles and permissions to access control
    access_control.add_role("Client", ["ViewAccountBalance", "ViewInvestments", "ViewContactDetails"])
    access_control.add_role("PremiumClient", ["ModifyInvestmentPortfolio", "ViewFinancialPlannerDetails", "ViewInvestmentAnalystDetails"])
    access_control.add_role("Employee", ["ViewAccountBalance", "ViewInvestments"])
    access_control.add_role("FinancialPlanner", ["ViewMoneyMarketInstruments", "ModifyInvestmentPortfolio"])
    access_control.add_role("InvestmentAnalyst", ["ViewMoneyMarketInstruments", "ViewDerivativesTrading", "ViewInterestInstruments", "ViewPrivateConsumerInstruments"])
    access_control.add_role("TechnicalSupport", ["ViewClientInformation", "RequestClientAccountAccess"])
    access_control.add_role("Teller", [])

    # Initialize Command Line UI
    command_line_ui = CommandLineUI(password_file, user_enrollment, user_verification, access_control)
    # Run Command Line UI
    command_line_ui.run()

if __name__ == "__main__":
    main()  