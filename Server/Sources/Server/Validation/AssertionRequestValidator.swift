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
        let payload = assertionObject.authenticatorData.rawValue + clientDataHash
        let nonce = Data(SHA256.hash(data: payload))

        guard verifySignature(
            assertionObject.signature,
            payload: payload,
            nonce: nonce,
            publicKey: publicKey
        ) else {
            throw AssertionValidationError.invalidSignature
        }

        _ = keyID // keyID is used for DB lookup before cryptographic validation.
        return newCounter
    }

    private func verifySignature(
        _ signature: Data,
        payload: Data,
        nonce: Data,
        publicKey: Data
    ) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey) else {
            return false
        }

        // App Attest assertion signatures are DER in practice, but support raw as fallback.
        let parsedSignature: P256.Signing.ECDSASignature
        if let der = try? P256.Signing.ECDSASignature(derRepresentation: signature) {
            parsedSignature = der
        } else if let raw = try? P256.Signing.ECDSASignature(rawRepresentation: signature) {
            parsedSignature = raw
        } else {
            return false
        }

        // Try documented nonce verification first, then payload compatibility fallback.
        if key.isValidSignature(parsedSignature, for: nonce) {
            return true
        }

        if key.isValidSignature(parsedSignature, for: payload) {
            return true
        }

        return false
    }
}
