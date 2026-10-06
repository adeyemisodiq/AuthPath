class Resource:
    def __init__(
        self,
        type: str,
        id: str,
        owner: str | None = None,
        attributes: dict[str, str] | None = None,
        relationships: dict[str, list[str]] | None = None
    ):
        self.type = type
        self.id = id
        self.owner = owner
        self.attributes = (
            attributes if attributes is not None else {}
        )
        self.relationships = (
            relationships if relationships is not None else {}
        )

    def __repr__(self):
        return (
            f"Resource("
            f"type={self.type!r}, "
            f"id={self.id!r}, "
            f"owner={self.owner!r}, "
            f"attributes={self.attributes!r}, "
            f"relationships={self.relationships!r}"
            f")"
        )