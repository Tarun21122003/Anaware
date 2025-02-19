class BreachChecker:
    def __init__(self):
        pass
    
    @staticmethod
    def check_breaches(email):
        """
        Returns a message indicating that the check will be performed on HaveIBeenPwned.
        """
        return f"Redirecting to HaveIBeenPwned to check: {email}"