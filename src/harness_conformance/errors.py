class ConformanceError(ValueError):
    """Bounded, user-safe contract failure."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message

    def __str__(self) -> str:
        return f"{self.reason}: {self.message}"
