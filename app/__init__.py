
"""App package initializer.

Provides a simple hello_world function and CLI entry when run directly.
"""

def hello_world() -> str:
	"""Return a simple Hello World string."""
	return "Hello, world!"


__all__ = ["hello_world"]


if __name__ == "__main__":
	print(hello_world())

