from enum import StrEnum
from pydantic import BaseModel, Field, model_validator


class Component(BaseModel):
    name: str = Field(min_length=1)
    type: str = Field(min_length=1)
    internet_facing: bool = False
    public: bool = False
    sensitive_data: bool = False
    authentication: str | None = None
    permissions: list[str] = Field(default_factory=list)


class Connection(BaseModel):
    source: str
    target: str
    protocol: str | None = None

    @model_validator(mode="before")
    @classmethod
    def parse_arrow_form(cls, value: object) -> object:
        if isinstance(value, str) and "->" in value:
            source, target = (part.strip() for part in value.split("->", 1))
            return {"source": source, "target": target}
        return value


class Architecture(BaseModel):
    name: str = "Unnamed application"
    description: str | None = None
    components: list[Component] = Field(min_length=1)
    connections: list[Connection] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references(self) -> "Architecture":
        names = {component.name for component in self.components}
        missing = {endpoint for link in self.connections for endpoint in (link.source, link.target) if endpoint not in names and endpoint.lower() != "internet"}
        if missing:
            raise ValueError(f"Connections reference unknown components: {', '.join(sorted(missing))}")
        return self


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Threat(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    affected_asset: str
    cwe: str | None = None
    attack_path: list[str]
    rationale: str
    recommended_control: str
    validation: str
    score: int = Field(ge=1, le=25)


class AttackPath(BaseModel):
    path: list[str]
    blast_radius: Severity
    rationale: str


class SecurityReport(BaseModel):
    application: str
    threat_count: int
    summary: dict[Severity, int]
    threats: list[Threat]
    attack_paths: list[AttackPath]
