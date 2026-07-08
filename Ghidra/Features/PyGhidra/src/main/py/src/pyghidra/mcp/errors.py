"""Ghidra MCP error definitions."""


class GhidraMCPError(Exception):
    """Base exception for Ghidra MCP errors."""

    pass


class BinaryNotLoadedError(GhidraMCPError):
    """Raised when no binary is loaded."""

    def __init__(self, message: str = "No binary loaded. Use load_binary first."):
        super().__init__(message)


class AnalysisError(GhidraMCPError):
    """Raised when analysis fails."""

    pass


class FunctionNotFoundError(GhidraMCPError):
    """Raised when function is not found."""

    def __init__(self, address: int):
        super().__init__(f"Function not found at address {address:#x}")
        self.address = address


class InvalidAddressError(GhidraMCPError):
    """Raised when address is invalid."""

    def __init__(self, address: int):
        super().__init__(f"Invalid address: {address:#x}")
        self.address = address


class DecompilationError(GhidraMCPError):
    """Raised when decompilation fails."""

    def __init__(self, function_name: str, reason: str):
        super().__init__(f"Failed to decompile {function_name}: {reason}")
        self.function_name = function_name
        self.reason = reason
