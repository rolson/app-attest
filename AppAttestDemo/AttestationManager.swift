import AppAttest
import Foundation

final class AttestationManager: ChallengeProvider {

    private let backendService: BackendIntegrationService
    private let appAttest: AppAttestProtocol
    private var keyID: String?

    init(
        appAttest: AppAttestProtocol = AppAttest(),
        backendService: BackendIntegrationService = BackendIntegrationService()
    ) {
        self.backendService = backendService
        self.appAttest = appAttest
    }

    func challenge(for keyID: String) async throws -> Data {
        self.keyID = keyID
        return try await backendService.challenge(for: keyID)
    }

    func submitAttestation() async throws {
        let attestation = try await appAttest
            .fetchAttestation(challengeProvider: self)

        guard let keyID else {
            fatalError("Attestation must have requested a challenge")
        }
        try await backendService.attest(keyID: keyID, attestation)
    }

    func getAssertion() async throws -> Data {
        guard let keyID else {
            fatalError("Key must ready have been attested before it can be asserted")
        }

        return try await appAttest.fetchAssertion(
            keyID: keyID,
            challenge: challenge(for: keyID)
        )
    }

    func helloWorld() async throws {
        guard let keyID else {
            fatalError("Key must already have been attested before calling hello-world")
        }

        let assertion = try await appAttest.fetchAssertion(
            keyID: keyID,
            challenge: challenge(for: keyID)
        )
        try await backendService.helloWorld(assertion: assertion, keyID: keyID)
    }
}
