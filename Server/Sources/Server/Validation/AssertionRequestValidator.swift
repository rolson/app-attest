import AttestationDecoding
import Crypto
import Foundation
import Security

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

        let secKey = try makeSecKey(fromX963PublicKey: publicKey)
        guard verifySignature(
            assertionObject.signature,
            payload: payload,
            nonce: nonce,
            publicKey: publicKey,
            with: secKey
        ) else {
            throw AssertionValidationError.invalidSignature
        }

        _ = keyID // keyID is used for DB lookup before cryptographic validation.
        return newCounter
    }

    private func makeSecKey(fromX963PublicKey publicKey: Data) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 256
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            publicKey as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            throw error?.takeRetainedValue() as Error? ?? AssertionValidationError.invalidSignature
        }
        return key
    }

    private func verifySignature(
        _ signature: Data,
        payload: Data,
        nonce: Data,
        publicKey: Data,
        with key: SecKey
    ) -> Bool {
        // Reference implementations successfully verify SHA256-with-ECDSA over the nonce as a message.
        if secKeyVerify(
            key,
            algorithm: .ecdsaSignatureMessageX962SHA256,
            signedData: nonce,
            signature: signature
        ) {
            return true
        }

        if secKeyVerify(
            key,
            algorithm: .ecdsaSignatureDigestX962SHA256,
            signedData: nonce,
            signature: signature
        ) {
            return true
        }

        if secKeyVerify(
            key,
            algorithm: .ecdsaSignatureMessageX962SHA256,
            signedData: payload,
            signature: signature
        ) {
            return true
        }

        if secKeyVerify(
            key,
            algorithm: .ecdsaSignatureDigestX962SHA256,
            signedData: Data(SHA256.hash(data: payload)),
            signature: signature
        ) {
            return true
        }

        // CryptoKit sometimes succeeds where Security does not, for equivalent DER signatures.
        if let cryptoKey = try? P256.Signing.PublicKey(x963Representation: publicKey),
           let derSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature) {
            if cryptoKey.isValidSignature(derSignature, for: nonce) {
                return true
            }
            if cryptoKey.isValidSignature(derSignature, for: payload) {
                return true
            }
        }

        return false
    }

    private func secKeyVerify(
        _ key: SecKey,
        algorithm: SecKeyAlgorithm,
        signedData: Data,
        signature: Data
    ) -> Bool {
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(
            key,
            algorithm,
            signedData as CFData,
            signature as CFData,
            &error
        )
    }
}
