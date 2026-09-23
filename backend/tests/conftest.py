import os
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="sealingdesk-test-"))
os.environ.setdefault("STATIC_DIR", tempfile.mkdtemp(prefix="sealingdesk-static-"))
