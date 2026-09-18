"""Головний файл лабораторної роботи №1: демонстрація завдань 1–3."""

from __future__ import annotations

import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")),
)

from task1 import run_password_analysis
from task2 import run_access_control
from task3 import run_auth_workflow

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# --- Завдання 1 (варіант 9) ---
PASSWORDS = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]
CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {
    "plain",
    "member",
    "regular",
    "ordinary",
    "usual",
    "user",
}

# --- Завдання 2 (варіант 9) ---
USERS = {
    "cloud_architect": {
        "role": "cloud_security",
        "clearance": 4,
        "department": "Cloud",
        "active": True,
    },
    "devops_engineer": {
        "role": "devops",
        "clearance": 3,
        "department": "DevOps",
        "active": True,
    },
    "qa_tester": {
        "role": "quality_assurance",
        "clearance": 2,
        "department": "QA",
        "active": True,
    },
    "partner_access": {
        "role": "partner",
        "clearance": 2,
        "department": "Partnership",
        "active": True,
    },
    "migrated_user": {
        "role": "migrated",
        "clearance": 1,
        "department": "Migration",
        "active": False,
    },
}
RESOURCES = [
    ("cloud_configs", 4),
    ("deployment_pipelines", 3),
    ("test_environments", 2),
    ("partner_apis", 2),
    ("infrastructure_code", 4),
    ("shared_resources", 1),
    ("container_registry", 3),
    ("secrets_vault", 4),
    ("build_artifacts", 2),
    ("public_endpoints", 1),
]
SECURITY_LEVELS = (
    "Development",
    "Staging",
    "Production",
    "Critical Infrastructure",
)
BLOCKED_USERS = {"migrated_user", "container_breach", "pipeline_compromise"}

# --- Завдання 3 (варіант 9) ---
HASH_ALGORITHM = "sha224"
MIN_PASSWORD_LENGTH = 13
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"
USERS_TO_REGISTER = (
    ("cloud_architect", "CloudVault@Secure13"),
    ("devops_engineer", "Pipeline$Deploy14"),
    ("qa_tester", "Quality@Assure15"),
    ("partner_access", "Partner#Access16"),
    ("infra_admin", "Infra!Admin2024X"),
    ("secrets_manager", "Secrets@Vault17"),
    ("build_operator", "Build$Operator18"),
    ("audit_reader", "Audit@Reader19"),
    ("api_gateway", "Gateway#Secure20"),
    ("backup_agent", "Backup@Agent2024Z"),
)


def _section(title: str) -> None:
    line = "=" * len(title)
    print(f"\n{line}\n{title}\n{line}\n")


def main() -> None:
    print("Лабораторна робота №1")
    print(
        f"Студент: {STUDENT_NAME}, група {GROUP_NAME}, "
        f"варіант {VARIANT_NUMBER}",
    )

    _section("Завдання 1: Комплексний аналізатор надійності паролів")
    run_password_analysis(PASSWORDS, CRITERIA, FORBIDDEN_PASSWORDS)

    _section("Завдання 2: Багаторівнева система контролю доступу")
    run_access_control(USERS, RESOURCES, SECURITY_LEVELS, BLOCKED_USERS)

    _section("Завдання 3: Хешування, CSV-база та JSON-логування")
    run_auth_workflow(
        HASH_ALGORITHM,
        MIN_PASSWORD_LENGTH,
        PERSONAL_SALT,
        USERS_TO_REGISTER,
    )


if __name__ == "__main__":
    main()
