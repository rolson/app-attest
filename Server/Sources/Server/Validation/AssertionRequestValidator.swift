import AttestationDecoding
import Crypto
import Foundation

enum AssertionValidationError: Error {
    case invalidSignature
    case wrongRelyingParty
    case nonMonotonicCounter
}

struct AssertionRequestValidator: Sendable {
    private let appIDHash: Data

    init(appID: String) {
        self.appIDHash = Data(SHA256.hash(data: Data(appID.utf8)))
    }

    func validate(
        assertion: Data,
        challenge: Data,
        keyID: String,
        publicKey: Data,
        minimumCounter: Int
    ) throws -> Int {
        let assertionObject = try AssertionDecoder().decode(data: assertion)

        guard assertionObject.authenticatorData.relyingPartyIDHash == appIDHash else {
            throw AssertionValidationError.wrongRelyingParty
        }

        let newCounter = assertionObject.authenticatorData.counter
        guard newCounter > minimumCounter else {
            throw AssertionValidationError.nonMonotonicCounter
        }

        let clientDataHash = Data(SHA256.hash(data: challenge))
        let signedPayload = assertionObject.authenticatorData.rawValue + clientDataHash
        let key = try P256.Signing.PublicKey(derRepresentation: publicKey)
        let signature = try P256.Signing.ECDSASignature(
            derRepresentation: assertionObject.signature
        )
        guard key.isValidSignature(signature, for: signedPayload) else {
            throw AssertionValidationError.invalidSignature
        }

        _ = keyID // keyID is used for DB lookup before cryptographic validation.
        return newCounter
    }
}
