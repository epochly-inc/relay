"""ACEF Package — core evidence package builder.

The primary API for creating ACEF Evidence Bundles.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from acef.errors import ACEFError, ACEFSchemaError
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.enums import (
    ActorRole,
    AuditEventType,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    RECORD_TYPES,
    RelationshipType,
    RiskClassification,
    SubjectType,
    TrustLevel,
)
from acef.models.manifest import AuditTrailEntry, Manifest, ProfileEntry, RecordFileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    AttachmentRef,
    Attestation,
    CollectorInfo,
    EntityRefs,
    RecordEnvelope,
    RecordRetention,
)
from acef.models.subjects import LifecycleEntry, Subject


class Package:
    """ACEF Evidence Package builder.

    Usage:
        pkg = Package(producer={"name": "my-tool", "version": "1.0"})
        system = pkg.add_subject(subject_type="ai_system", name="My System")
        pkg.record("risk_register", provisions=["article-9"], payload={...})
        pkg.export("output.acef/")
    """

    def __init__(
        self,
        producer: dict[str, str] | ProducerInfo | None = None,
        *,
        retention_policy: dict[str, Any] | RetentionPolicy | None = None,
        prior_package_ref: str | None = None,
    ) -> None:
        if producer is None:
            producer = ProducerInfo(name="acef-sdk", version="0.1.0")
        elif isinstance(producer, dict):
            producer = ProducerInfo(**producer)

        retention = None
        if retention_policy is not None:
            if isinstance(retention_policy, dict):
                retention = RetentionPolicy(**retention_policy)
            else:
                retention = retention_policy

        self._metadata = PackageMetadata(
            producer=producer,
            prior_package_ref=prior_package_ref,
            retention_policy=retention,
        )
        self._versioning = Versioning()
        self._subjects: list[Subject] = []
        self._entities = EntitiesBlock()
        self._profiles: list[ProfileEntry] = []
        self._records: list[RecordEnvelope] = []
        self._audit_trail: list[AuditTrailEntry] = []
        self._attachments: dict[str, bytes] = {}  # path -> content
        self._signed = False
        self._signature_key: str | None = None
        self._signature_method: str | None = None

        # Add creation audit entry
        self._audit_trail.append(
            AuditTrailEntry(
                event_type=AuditEventType.CREATED,
                timestamp=self._metadata.timestamp,
                description="Initial package creation",
            )
        )

    @property
    def metadata(self) -> PackageMetadata:
        return self._metadata

    @property
    def versioning(self) -> Versioning:
        """Public read-only access to versioning info."""
        return self._versioning

    @property
    def subjects(self) -> list[Subject]:
        return list(self._subjects)

    @property
    def entities(self) -> EntitiesBlock:
        return self._entities

    @property
    def records(self) -> list[RecordEnvelope]:
        return list(self._records)

    @property
    def profiles(self) -> list[ProfileEntry]:
        return list(self._profiles)

    @property
    def audit_trail(self) -> list[AuditTrailEntry]:
        """Public read-only access to audit trail entries."""
        return list(self._audit_trail)

    @property
    def attachments(self) -> dict[str, bytes]:
        """Public read-only access to attachment content."""
        return dict(self._attachments)

    @property
    def is_signed(self) -> bool:
        """Whether this package is marked for signing during export."""
        return self._signed

    @property
    def signing_key(self) -> str | None:
        """Path to the signing key, if signing is enabled."""
        return self._signature_key

    def add_subject(
        self,
        subject_type: str | SubjectType,
        name: str,
        *,
        version: str = "1.0.0",
        provider: str = "",
        risk_classification: str | RiskClassification = RiskClassification.MINIMAL_RISK,
        modalities: list[str] | None = None,
        lifecycle_phase: str | LifecyclePhase = LifecyclePhase.DEVELOPMENT,
        lifecycle_timeline: list[dict[str, str]] | None = None,
    ) -> Subject:
        """Add a subject (AI system or model) to the package.

        Returns:
            The created Subject with generated URN.
        """
        if isinstance(subject_type, str):
            subject_type = SubjectType(subject_type)
        if isinstance(risk_classification, str):
            risk_classification = RiskClassification(risk_classification)
        if isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        timeline = []
        if lifecycle_timeline:
            timeline = [LifecycleEntry(**entry) for entry in lifecycle_timeline]

        subject = Subject(
            subject_type=subject_type,
            name=name,
            version=version,
            provider=provider,
            risk_classification=risk_classification,
            modalities=modalities or [],
            lifecycle_phase=lifecycle_phase,
            lifecycle_timeline=timeline,
        )
        self._subjects.append(subject)
        return subject

    def add_component(
        self,
        name: str,
        type: str | ComponentType,
        *,
        version: str = "1.0.0",
        subject_refs: list[str] | None = None,
        provider: str = "",
    ) -> Component:
        """Add a component entity to the package.

        Returns:
            The created Component with generated URN.
        """
        if isinstance(type, str):
            type = ComponentType(type)

        component = Component(
            name=name,
            type=type,
            version=version,
            subject_refs=subject_refs or [],
            provider=provider,
        )
        self._entities.components.append(component)
        return component

    def add_dataset(
        self,
        name: str,
        *,
        version: str = "1.0.0",
        source_type: str | DatasetSourceType = DatasetSourceType.LICENSED,
        modality: str | DatasetModality = DatasetModality.TEXT,
        size: dict[str, Any] | None = None,
        subject_refs: list[str] | None = None,
    ) -> Dataset:
        """Add a dataset entity to the package.

        Returns:
            The created Dataset with generated URN.
        """
        if isinstance(source_type, str):
            source_type = DatasetSourceType(source_type)
        if isinstance(modality, str):
            modality = DatasetModality(modality)

        dataset = Dataset(
            name=name,
            version=version,
            source_type=source_type,
            modality=modality,
            size=size or {"records": 0, "size_gb": 0.0},
            subject_refs=subject_refs or [],
        )
        self._entities.datasets.append(dataset)
        return dataset

    def add_actor(
        self,
        name: str = "",
        *,
        role: str | ActorRole = ActorRole.PROVIDER,
        organization: str = "",
    ) -> Actor:
        """Add an actor entity to the package.

        Returns:
            The created Actor with generated URN.
        """
        if isinstance(role, str):
            role = ActorRole(role)

        actor = Actor(name=name, role=role, organization=organization)
        self._entities.actors.append(actor)
        return actor

    def add_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str | RelationshipType,
        *,
        description: str = "",
    ) -> Relationship:
        """Add a relationship between entities.

        Returns:
            The created Relationship.
        """
        if isinstance(relationship_type, str):
            relationship_type = RelationshipType(relationship_type)

        rel = Relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type,
            description=description,
        )
        self._entities.relationships.append(rel)
        return rel

    def add_profile(
        self,
        profile_id: str,
        *,
        provisions: list[str] | None = None,
        template_version: str = "1.0.0",
    ) -> ProfileEntry:
        """Declare a regulation profile for this package.

        Returns:
            The created ProfileEntry.
        """
        entry = ProfileEntry(
            profile_id=profile_id,
            template_version=template_version,
            applicable_provisions=provisions or [],
        )
        self._profiles.append(entry)
        return entry

    def record(
        self,
        record_type: str,
        *,
        provisions: list[str] | None = None,
        payload: dict[str, Any] | None = None,
        obligation_role: str | ObligationRole | None = None,
        entity_refs: dict[str, list[str]] | EntityRefs | None = None,
        confidentiality: str | Confidentiality = Confidentiality.PUBLIC,
        redaction_method: str | None = None,
        access_policy: dict[str, Any] | None = None,
        trust_level: str | TrustLevel = TrustLevel.SELF_ATTESTED,
        lifecycle_phase: str | LifecyclePhase | None = None,
        collector: dict[str, str] | CollectorInfo | None = None,
        attachments: list[dict[str, Any] | AttachmentRef] | None = None,
        attestation: dict[str, Any] | Attestation | None = None,
        retention: dict[str, Any] | RecordRetention | None = None,
        timestamp: str | None = None,
    ) -> RecordEnvelope:
        """Record an evidence record.

        Args:
            record_type: One of the 16 ACEF v1 record types.
            provisions: Regulatory provisions this evidence supports.
            payload: The type-specific evidence payload.
            obligation_role: Who produced this evidence.
            entity_refs: Links to subjects, components, datasets, actors.
            confidentiality: Evidence confidentiality level.
            trust_level: Evidence trust provenance.
            lifecycle_phase: Which lifecycle phase this relates to.
            collector: Tool/person that collected this evidence.
            attachments: File references in artifacts/.
            attestation: Cryptographic attestation.
            retention: Per-record retention requirements.
            timestamp: Override timestamp (ISO 8601).

        Returns:
            The created RecordEnvelope.

        Raises:
            ACEFSchemaError: If record_type is not recognized.
            ACEFError: If timestamp is not valid ISO 8601.
        """
        # Validate record type - allow extension types with x- prefix
        if record_type not in RECORD_TYPES and not record_type.startswith("x-"):
            raise ACEFSchemaError(
                f"Unknown record_type: {record_type!r}",
                code="ACEF-003",
            )

        if isinstance(obligation_role, str):
            obligation_role = ObligationRole(obligation_role)
        if isinstance(confidentiality, str):
            confidentiality = Confidentiality(confidentiality)
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)
        if isinstance(lifecycle_phase, str):
            lifecycle_phase = LifecyclePhase(lifecycle_phase)

        if isinstance(entity_refs, dict):
            entity_refs = EntityRefs(**entity_refs)
        elif entity_refs is None:
            entity_refs = EntityRefs()

        if isinstance(collector, dict):
            collector = CollectorInfo(**collector)

        parsed_attachments: list[AttachmentRef] = []
        if attachments:
            for att in attachments:
                if isinstance(att, dict):
                    parsed_attachments.append(AttachmentRef(**att))
                else:
                    parsed_attachments.append(att)

        if isinstance(attestation, dict):
            attestation = Attestation(**attestation)
        if isinstance(retention, dict):
            retention = RecordRetention(**retention)

        envelope = RecordEnvelope(
            record_type=record_type,
            provisions_addressed=provisions or [],
            payload=payload or {},
            obligation_role=obligation_role,
            entity_refs=entity_refs,
            confidentiality=confidentiality,
            redaction_method=redaction_method,
            access_policy=access_policy,
            trust_level=trust_level,
            lifecycle_phase=lifecycle_phase,
            collector=collector,
            attachments=parsed_attachments,
            attestation=attestation,
            retention=retention,
        )
        if timestamp:
            try:
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError) as e:
                raise ACEFError(
                    f"Invalid ISO 8601 timestamp: {timestamp!r}",
                    code="ACEF-050",
                ) from e
            envelope.timestamp = timestamp

        self._records.append(envelope)
        return envelope

    def add_attachment(self, path: str, content: bytes) -> None:
        """Add an attachment file to be included in artifacts/.

        Args:
            path: Relative path within artifacts/ (e.g., 'eval-report-v3.pdf').
            content: Raw file content.

        Raises:
            ACEFError: If the path contains traversal sequences, backslashes, or is absolute.
        """
        # Validate raw input path BEFORE prefix — catch absolute paths and traversal
        # on the raw caller-supplied value
        _validate_raw_attachment_path(path)

        if not path.startswith("artifacts/"):
            path = f"artifacts/{path}"

        # Validate final path — defense in depth
        _validate_attachment_path(path)

        self._attachments[path] = content

    def sign(self, key: str, *, method: str = "jws") -> None:
        """Mark this package for signing during export.

        The actual signing happens during export() when the content hashes
        are computed.

        Args:
            key: Path to the private key file (PEM format).
            method: Signing method ('jws' only for v1).
        """
        self._signed = True
        self._signature_key = key
        self._signature_method = method

    def build_manifest(self) -> Manifest:
        """Build the Manifest object from current package state.

        Uses the same deterministic sharding algorithm as the export module
        to ensure manifest record_files paths match actual file layout.

        Returns:
            A Manifest ready for serialization.
        """
        from acef.records_util import compute_shard_boundaries, sort_records

        # Build record_files index by grouping records by type
        records_by_type: dict[str, list[RecordEnvelope]] = {}
        for rec in self._records:
            records_by_type.setdefault(rec.record_type, []).append(rec)

        record_files: list[RecordFileEntry] = []
        for record_type, recs in sorted(records_by_type.items()):
            sorted_recs = sort_records(recs)
            shards = compute_shard_boundaries(sorted_recs)

            if len(shards) == 1:
                path = f"records/{record_type}.jsonl"
                record_files.append(
                    RecordFileEntry(path=path, record_type=record_type, count=len(shards[0]))
                )
            else:
                for i, shard in enumerate(shards):
                    shard_num = str(i + 1).zfill(4)
                    path = f"records/{record_type}/{record_type}.{shard_num}.jsonl"
                    record_files.append(
                        RecordFileEntry(path=path, record_type=record_type, count=len(shard))
                    )

        return Manifest(
            metadata=self._metadata,
            versioning=self._versioning,
            subjects=self._subjects,
            entities=self._entities,
            profiles=self._profiles,
            record_files=record_files,
            audit_trail=self._audit_trail,
        )

    def export(self, path: str) -> None:
        """Export the package to a directory or archive.

        If path ends with .tar.gz, exports as an archive.
        Otherwise, exports as a directory bundle.

        Args:
            path: Output path (directory or .acef.tar.gz).
        """
        from acef.export import export_directory, export_archive

        if path.endswith(".tar.gz"):
            export_archive(self, path)
        else:
            export_directory(self, path)

    @classmethod
    def _init_from_parts(
        cls,
        *,
        metadata: PackageMetadata,
        versioning: Versioning,
        subjects: list[Subject],
        entities: EntitiesBlock,
        profiles: list[ProfileEntry],
        records: list[RecordEnvelope],
        audit_trail: list[AuditTrailEntry],
        attachments: dict[str, bytes] | None = None,
    ) -> "Package":
        """Create a Package from pre-parsed parts (deserialization path).

        This is the approved way for loader.py, merge.py, and redaction.py
        to construct Package instances without reaching into private attributes.

        Args:
            metadata: Fully constructed PackageMetadata.
            versioning: Versioning info.
            subjects: List of Subject instances.
            entities: EntitiesBlock with all entity types.
            profiles: List of ProfileEntry instances.
            records: List of RecordEnvelope instances.
            audit_trail: List of AuditTrailEntry instances.
            attachments: Dict mapping artifact paths to bytes content.

        Returns:
            A fully constructed Package.
        """
        pkg = cls.__new__(cls)
        pkg._metadata = metadata
        pkg._versioning = versioning
        pkg._subjects = list(subjects)
        pkg._entities = entities
        pkg._profiles = list(profiles)
        pkg._records = list(records)
        pkg._audit_trail = list(audit_trail)
        pkg._attachments = dict(attachments) if attachments else {}
        pkg._signed = False
        pkg._signature_key = None
        pkg._signature_method = None
        return pkg


def _validate_raw_attachment_path(path: str) -> None:
    """Validate raw caller-supplied attachment path before prefix is applied.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The raw caller-supplied path.

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )


def _validate_attachment_path(path: str) -> None:
    """Validate a final attachment path for safety.

    Rejects:
    - Absolute paths (starting with '/')
    - Path traversal sequences ('..' segments)
    - Current-directory segments ('.' segments)
    - Paths not under artifacts/
    - Backslash separators (spec 3.1.1: forward slashes only)

    Args:
        path: The attachment path to validate (with artifacts/ prefix).

    Raises:
        ACEFError: If the path is unsafe.
    """
    # M4 (Implementer R2): Reject backslash separators per spec 3.1.1
    if "\\" in path:
        raise ACEFError(
            f"Backslash separators not allowed in attachment path (use forward slashes): {path!r}",
            code="ACEF-052",
        )

    if path.startswith("/"):
        raise ACEFError(
            f"Absolute attachment path not allowed: {path!r}",
            code="ACEF-052",
        )

    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFError(
                f"Path traversal detected in attachment path: {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFError(
                f"Current-directory segment (.) not allowed in attachment path: {path!r}",
                code="ACEF-052",
            )

    if not path.startswith("artifacts/"):
        raise ACEFError(
            f"Attachment path must be under artifacts/: {path!r}",
            code="ACEF-052",
        )
