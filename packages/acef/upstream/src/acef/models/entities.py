"""ACEF entity models — Components, Datasets, Actors, Relationships."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from acef.models.enums import (
    ActorRole,
    ComponentType,
    DatasetModality,
    DatasetSourceType,
    RelationshipType,
)
from acef.models.urns import URNType, generate_urn


class Component(BaseModel):
    """A subsystem, model version, or deployment component."""

    component_id: str = Field(default_factory=lambda: generate_urn(URNType.COMPONENT))
    name: str
    type: ComponentType
    version: str = "1.0.0"
    subject_refs: list[str] = Field(default_factory=list)
    provider: str = ""

    @property
    def id(self) -> str:
        return self.component_id


class DatasetSize(BaseModel):
    """Dataset size information."""

    records: int = 0
    size_gb: float = 0.0


class Dataset(BaseModel):
    """A training, validation, or test dataset."""

    dataset_id: str = Field(default_factory=lambda: generate_urn(URNType.DATASET))
    name: str
    version: str = "1.0.0"
    source_type: DatasetSourceType = DatasetSourceType.LICENSED
    modality: DatasetModality = DatasetModality.TEXT
    size: DatasetSize | dict[str, Any] = Field(default_factory=lambda: DatasetSize())
    subject_refs: list[str] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return self.dataset_id


class Actor(BaseModel):
    """A person or organization involved in the AI system lifecycle."""

    actor_id: str = Field(default_factory=lambda: generate_urn(URNType.ACTOR))
    role: ActorRole = ActorRole.PROVIDER
    name: str = ""
    organization: str = ""

    @property
    def id(self) -> str:
        return self.actor_id


class Relationship(BaseModel):
    """An entity graph edge (W3C PROV-compatible)."""

    source_ref: str
    target_ref: str
    relationship_type: RelationshipType
    description: str = ""


class EntitiesBlock(BaseModel):
    """The complete entity graph for a package."""

    components: list[Component] = Field(default_factory=list)
    datasets: list[Dataset] = Field(default_factory=list)
    actors: list[Actor] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
