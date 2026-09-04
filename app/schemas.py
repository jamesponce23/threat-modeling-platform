"""Pydantic request/response models for the JSON API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class SubmissionCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=200)
    owner_email: EmailStr
    repo_url: str = Field(min_length=1)
    ref: str = "main"
    answers: dict[str, str]


class SubmissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    source_type: str
    ref: str | None = None
    commit_sha: str | None = None
    status: str
    submitted_at: datetime


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    owner_email: str
    repo_url: str | None = None
    created_at: datetime
