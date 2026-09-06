from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class EmailCase(Base):
    __tablename__ = "email_cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    sender = Column(String(512), nullable=True)
    recipient = Column(String(512), nullable=True)
    subject = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    verdict = Column(String(32), nullable=False, default="SAFE")  # SAFE, SUSPICIOUS, CRITICAL
    raw_intel = Column(JSON, nullable=False)  # Complete forensic structured payload
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user = relationship("User", back_populates="cases")

    def __repr__(self) -> str:
        return f"<EmailCase id={self.id} case_id={self.case_id} verdict={self.verdict} score={self.risk_score}>"
