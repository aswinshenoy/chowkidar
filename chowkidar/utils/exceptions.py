class AuthError(Exception):
    def __init__(self, message, code=None):
        if code:
            self.code = code
        self.message = message
        super().__init__(message)


class PermissionDenied(Exception):
    def __init__(self, message, code=None):
        if code:
            self.code = code
        self.message = message
        super().__init__(message)


__all__ = [
    "AuthError",
    "PermissionDenied"
]
