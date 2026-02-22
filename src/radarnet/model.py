from __future__ import annotations

from dataclasses import dataclass, field


class ValidationError(ValueError):
    """Raised when the network model contains invalid values."""


@dataclass(frozen=True)
class Service:
    """Represents a network-facing service on a host."""

    name: str
    port: int
    public: bool = False
    encrypted: bool = True
    authenticated: bool = True
    criticality: int = 3

    def validate(self) -> None:
        if not self.name.strip():
            raise ValidationError("service.name must be non-empty")
        if not (1 <= self.port <= 65535):
            raise ValidationError(f"service.port must be between 1 and 65535, got {self.port}")
        if not (1 <= self.criticality <= 5):
            raise ValidationError(
                f"service.criticality must be between 1 and 5, got {self.criticality}"
            )


@dataclass(frozen=True)
class Node:
    """A machine/application node in the network."""

    id: str
    role: str
    services: tuple[Service, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not self.id.strip():
            raise ValidationError("node.id must be non-empty")
        if not self.role.strip():
            raise ValidationError(f"node[{self.id}].role must be non-empty")
        seen_ports: set[int] = set()
        for service in self.services:
            service.validate()
            if service.port in seen_ports:
                raise ValidationError(
                    f"node[{self.id}] contains duplicate port definition: {service.port}"
                )
            seen_ports.add(service.port)


@dataclass(frozen=True)
class Network:
    """A collection of nodes assessed by RadarNet."""

    name: str
    nodes: tuple[Node, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not self.name.strip():
            raise ValidationError("network.name must be non-empty")
        seen_ids: set[str] = set()
        for node in self.nodes:
            node.validate()
            if node.id in seen_ids:
                raise ValidationError(f"duplicate node id detected: {node.id}")
            seen_ids.add(node.id)
