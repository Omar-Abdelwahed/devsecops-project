import os
import tempfile

# Must be set before app.py is imported — app.py uses os.environ["SECRET_KEY"] (hard access).
os.environ["SECRET_KEY"] = "test-only-not-real"
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
