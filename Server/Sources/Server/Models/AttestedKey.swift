import Fluent
import Vapor

final class AttestedKey: Model, @unchecked Sendable {
    static let schema = "attested_keys"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "key_id")
    var keyID: String

    @Field(key: "public_key")
    var publicKey: Data

    @Field(key: "sign_count")
    var signCount: Int

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() { }

    init(id: UUID? = nil, keyID: String, publicKey: Data, signCount: Int = 0) {
        self.id = id
        self.keyID = keyID
        self.publicKey = publicKey
        self.signCount = signCount
    }
}
