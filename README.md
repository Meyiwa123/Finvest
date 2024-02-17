# Finvest Holdings Client Holdings and Information System
Welcome to the Finvest Holdings Client Holdings and Information System! This system provides functionalities for user enrollment, login, and access control based on predefined roles and permissions.

## Functionality Overview
1. User Enrollment
New users can enroll in the system by providing a username, password, and role. The system enforces password strength criteria and checks for common weak passwords.
2. Login
Registered users can log in to the system by providing their username and password. Upon successful login, users gain access to their personalized information based on their role and permissions.
3. Access Control
The system employs access control mechanisms based on roles and permissions. Different roles have different levels of access to system functionalities.

## Usage
To use the system, follow these steps:
1. Initialize Components: Initialize the PasswordFile, AccessControl, UserEnrollment, and UserVerification components.
2. Define Roles and Permissions: Add roles and their corresponding permissions to the AccessControl component.
3. Run Command Line UI: Execute the main function to start the command-line interface for user interaction.

## Components
1. AccessControl Class
Manages roles and permissions within the system.
Provides methods to add roles, check permissions, and retrieve permissions for a specific role.
2. PasswordFile Class
Handles operations related to storing and retrieving user credentials.
Utilizes SHA-256 hashing with a salt for secure password storage.
3. UserEnrollment Class
Facilitates the enrollment of new users into the system.
Ensures password strength and checks against common weak passwords during enrollment.
4. UserVerification Class
Verifies user credentials during login.
Compares hashed passwords to authenticate users.
5. CommandLineUI Class
Provides a command-line interface for users to interact with the system.
Offers options for user enrollment, login, and viewing user information based on roles.

## Roles and Permissions
The system supports the following predefined roles with associated permissions:

* Client: ViewAccountBalance, ViewInvestments, ViewContactDetails
* PremiumClient: ModifyInvestmentPortfolio, ViewFinancialPlannerDetails, ViewInvestmentAnalystDetails
* Employee: ViewAccountBalance, ViewInvestments
* FinancialPlanner: ViewMoneyMarketInstruments, ModifyInvestmentPortfolio
* InvestmentAnalyst: ViewMoneyMarketInstruments, ViewDerivativesTrading, ViewInterestInstruments, ViewPrivateConsumerInstruments
* TechnicalSupport: ViewClientInformation, RequestClientAccountAccess
* Teller: No specific permissions