import Crypto
import DeviceCheck

enum AppAttestError: Error {
    case unsupportedDevice
}

public final class AppAttest: AppAttestProtocol {
    let service: AttestationService

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

        return try await service.attestKey(
            keyID,
            clientDataHash: clientDataHash
        )
    }

    public func fetchAssertion(keyID: String, challenge: Data) async throws -> Data {
        let clientDataHash = Data(SHA256.hash(data: challenge))
        return try await service.generateAssertion(
            keyID,
            clientDataHash: clientDataHash
        )
    }
}
