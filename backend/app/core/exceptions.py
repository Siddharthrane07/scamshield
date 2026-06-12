class ScamShieldException(Exception):
    """Base exception for all ScamShield AI errors."""
    pass


class CacheException(ScamShieldException):
    """Raised when an operation in the caching layer fails."""
    pass


class SandboxException(ScamShieldException):
    """Raised when execution in the sandbox environment fails or times out."""
    pass


class IntelligenceException(ScamShieldException):
    """Raised when URL or domain threat intelligence gathering fails."""
    pass


class MLInferenceException(ScamShieldException):
    """Raised when the ML model inference fails."""
    pass
