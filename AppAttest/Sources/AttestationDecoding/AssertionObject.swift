import Foundation

public struct AssertionObject: Decodable {
    public let authenticatorData: AuthenticatorData
    public let signature: Data

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: DynamicCodingKey.self)

        // Apple assertion objects use `authenticatorData`; accept `authData` for compatibility.
        if let authData = try container.decodeIfPresent(Data.self, forKey: .init("authenticatorData"))
            ?? container.decodeIfPresent(Data.self, forKey: .init("authData")) {
            self.authenticatorData = AuthenticatorData(rawValue: authData)
        } else {
            throw DecodingError.keyNotFound(
                DynamicCodingKey("authenticatorData"),
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Missing authenticator data"
                )
            )
        }

        if let signature = try container.decodeIfPresent(Data.self, forKey: .init("signature"))
            ?? container.decodeIfPresent(Data.self, forKey: .init("sig")) {
            self.signature = signature
        } else {
            throw DecodingError.keyNotFound(
                DynamicCodingKey("signature"),
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Missing assertion signature"
                )
            )
        }
    }
}

extension AssertionObject: Sendable { }

private struct DynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}
