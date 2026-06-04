import Fluent

struct CreateAttestedKey: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("attested_keys")
            .id()
            .field("key_id", .string, .required)
            .field("public_key", .data, .required)
            .field("sign_count", .int, .required)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "key_id")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("attested_keys").delete()
    }
}
