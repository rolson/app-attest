import AppAttest
import Foundation

final class AttestationManager: ChallengeProvider {
    enum Error: Swift.Error {
        case missingKeyID
    }

    private let backendService: BackendIntegrationService
    private let appAttest: AppAttestProtocol

    init(
        appAttest: AppAttestProtocol = AppAttest(),
        backendService: BackendIntegrationService = BackendIntegrationService(),
    ) {
        self.backendService = backendService
        self.appAttest = appAttest
    }

    func challenge(for keyID: String) async throws -> Data {
        return try await backendService.challenge(for: keyID)
    }

    /// Performs attestation once per installed app by reusing a persisted key identifier.
    @discardableResult
    func submitAttestation() async throws -> Bool {
        if appAttest.keyID != nil {
            return false
        }

        let attestation = try await appAttest
            .fetchAttestation(challengeProvider: self)

        guard let keyID = appAttest.keyID else {
            throw Error.missingKeyID
        }

        do {
            try await backendService.attest(keyID: keyID, attestation)
            return true
        } catch {
            appAttest.resetKeyID()
            throw error
        }
    }

    func helloWorld() async throws {
        let assertion = try await appAttest.fetchAssertion(challengeProvider: self)
        try await backendService.helloWorld(
            assertion: assertion.assertion,
            keyID: assertion.keyID
        )
    }

    func resetAttestation() {
        appAttest.resetKeyID()
    }
}
