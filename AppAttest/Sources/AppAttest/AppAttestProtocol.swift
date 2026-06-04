import Foundation

public protocol AppAttestProtocol {
    func fetchAttestation(challengeProvider: ChallengeProvider) async throws -> Data
    func fetchAssertion(keyID: String, challenge: Data) async throws -> Data
}
