from pathlib import Path
import secrets
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
example = ROOT / ".env.example"
target = ROOT / ".env"

if not target.exists():
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")

changed = False
result = []
for line in target.read_text(encoding="utf-8").splitlines():
    if line.startswith("FLASK_SECRET_KEY="):
        value = line.split("=", 1)[1].strip()
        if not value or value.startswith("replace-"):
            line = "FLASK_SECRET_KEY=" + secrets.token_urlsafe(48)
            changed = True
    elif line.startswith("JWT_SECRET_KEY="):
        value = line.split("=", 1)[1].strip()
        if not value or value.startswith("replace-"):
            line = "JWT_SECRET_KEY=" + secrets.token_urlsafe(48)
            changed = True
    elif line.startswith("QUEUE_ENCRYPTION_KEY="):
        value = line.split("=", 1)[1].strip()
        if not value or value.startswith("replace-"):
            line = "QUEUE_ENCRYPTION_KEY=" + Fernet.generate_key().decode("ascii")
            changed = True
    result.append(line)
target.write_text("\n".join(result) + "\n", encoding="utf-8")
print(("Generated" if changed else "Verified") + f" secure secrets in {target}")
