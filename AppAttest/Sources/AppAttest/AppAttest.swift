import Crypto
import DeviceCheck
import Foundation

enum AppAttestError: Error {
    case unsupportedDevice
    case missingKeyID
}

public final class AppAttest: AppAttestProtocol {
    let service: AttestationService
    private static let keyIDStorageKey = "appattest.keyID"

    init(
        service: AttestationService
    ) {
        self.service = service
    }

    public convenience init() {
        self.init(
            service: DCAppAttestService.shared,
        )
    }

    public func fetchAttestation(challengeProvider: ChallengeProvider) async throws -> Data {
        guard service.isSupported else {
            throw AppAttestError.unsupportedDevice
        }

        let keyID = try await service.generateKey()
        let challenge = try await challengeProvider.challenge(for: keyID)
        let clientDataHash = Data(SHA256.hash(data: challenge))

        let attestation = try await service.attestKey(
            keyID,
            clientDataHash: clientDataHash
        )

        UserDefaults.standard.set(keyID, forKey: Self.keyIDStorageKey)
        return attestation
    }

    public func fetchAssertion(challengeProvider: ChallengeProvider) async throws -> (keyID: String, assertion: Data) {
        guard let keyID = keyID else {
            throw AppAttestError.missingKeyID
        }

        let challenge = try await challengeProvider.challenge(for: keyID)
        let clientDataHash = Data(SHA256.hash(data: challenge))
        let assertion = try await service.generateAssertion(
            keyID,
            clientDataHash: clientDataHash
        )
        return (keyID: keyID, assertion: assertion)
    }

    public var keyID: String? {
        UserDefaults.standard.string(forKey: Self.keyIDStorageKey)
    }

    public func resetKeyID() {
        UserDefaults.standard.removeObject(forKey: Self.keyIDStorageKey)
    }
}
