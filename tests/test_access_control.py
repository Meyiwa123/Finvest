from src.finvest import AccessControl

def test_access_control():
    access_control = AccessControl()
    access_control.add_role(
        "Client", ["ViewAccountBalance", "ViewInvestments", "ViewContactDetails"])
    assert access_control.check_permission(
        "Client", "ViewAccountBalance") == True
    assert access_control.check_permission(
        "Client", "ModifyInvestmentPortfolio") == False
    print("Test Case Passed")


if __name__ == '__main__':
    test_access_control()
