"""Audit ORM import marker — actual tables in repository.orm"""

# Tables are defined in repository.orm to avoid circular imports
# This module ensures audit tables are registered via import
from sentinel.repository.orm import AuditEventORM  # noqa: F401

__all__ = ["AuditEventORM"]
