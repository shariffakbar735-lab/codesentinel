import os

os.environ.setdefault("JWT_SECRET", "pytest-only-secret-do-not-use-outside-tests")
