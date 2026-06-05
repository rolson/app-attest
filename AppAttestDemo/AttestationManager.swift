import AppAttest
import Foundation

final class AttestationManager: ChallengeProvider {
    enum Error: Swift.Error {
        case missingKeyID
    }

    private let backendService: BackendIntegrationService
    private let appAttest: AppAttestProtocol
    private static let keyIDStorageKey = "appattest.keyID"
    private var keyID: String? {
        didSet {
            UserDefaults.standard.set(keyID, forKey: Self.keyIDStorageKey)
        }
    }

    init(
        appAttest: AppAttestProtocol = AppAttest(),
        backendService: BackendIntegrationService = BackendIntegrationService(),
    ) {
        self.backendService = backendService
        self.appAttest = appAttest
        self.keyID = UserDefaults.standard.string(forKey: Self.keyIDStorageKey)
    }

    func challenge(for keyID: String) async throws -> Data {
        self.keyID = keyID
        return try await backendService.challenge(for: keyID)
    }

    /// Performs attestation once per installed app by reusing a persisted key identifier.
    @discardableResult
    func submitAttestation() async throws -> Bool {
        if keyID != nil {
            return false
        }

        let attestation = try await appAttest
            .fetchAttestation(challengeProvider: self)

        guard let keyID else {
            throw Error.missingKeyID
        }

        do {
            try await backendService.attest(keyID: keyID, attestation)
            return true
        } catch {
            // Clear the generated key if server verification fails so the next try can re-attest cleanly.
            self.keyID = nil
            throw error
        }
    }

    func helloWorld() async throws {
        guard let keyID else {
            throw Error.missingKeyID
        }

        let challengeData = try await challenge(for: keyID)
        let assertion = try await appAttest.fetchAssertion(
            keyID: keyID,
            challenge: challengeData
        )
        try await backendService.helloWorld(
            assertion: assertion,
            keyID: keyID
        )
    }

    func resetAttestation() {
        keyID = nil
    }
}
