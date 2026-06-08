import Foundation

public protocol AppAttestProtocol {
    func fetchAttestation(challengeProvider: ChallengeProvider) async throws -> Data
    func fetchAssertion(challengeProvider: ChallengeProvider) async throws -> (keyID: String, assertion: Data)
    var keyID: String? { get }
    func resetKeyID()
}
