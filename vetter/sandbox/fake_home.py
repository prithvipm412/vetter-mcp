"""A disposable fake $HOME, seeded with canary secrets.

Each decoy file gets a unique ``VETTER-CANARY-<uuid4>`` token embedded in
otherwise plausible-looking content, so the sandbox can tell *which* decoy
(if any) ended up in an outbound request body.
"""

from __future__ import annotations

import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FakeHome:
    path: Path
    # relative path (e.g. ".ssh/id_rsa") -> canary token planted in that file
    canaries: dict[str, str] = field(default_factory=dict)

    def token_to_relpath(self) -> dict[str, str]:
        return {token: relpath for relpath, token in self.canaries.items()}


def _make_token() -> str:
    return f"VETTER-CANARY-{uuid.uuid4()}"


def create_fake_home(root: Path) -> FakeHome:
    """Populate ``root`` (must already exist and be empty) with decoy secrets."""
    home = FakeHome(path=root)

    ssh_dir = root / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    id_rsa_token = _make_token()
    id_rsa_path = ssh_dir / "id_rsa"
    id_rsa_path.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"vetter-sandbox-decoy {id_rsa_token}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    id_rsa_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    home.canaries[".ssh/id_rsa"] = id_rsa_token

    env_token = _make_token()
    (root / ".env").write_text(f"SECRET_KEY={env_token}\n")
    home.canaries[".env"] = env_token

    passwords_token = _make_token()
    (root / "passwords.txt").write_text(f"admin: {passwords_token}\n")
    home.canaries["passwords.txt"] = passwords_token

    aws_dir = root / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    aws_token = _make_token()
    (aws_dir / "credentials").write_text(
        "[default]\n"
        "aws_access_key_id=AKIADECOYDECOYDECOY\n"
        f"aws_secret_access_key={aws_token}\n"
    )
    home.canaries[".aws/credentials"] = aws_token

    return home
