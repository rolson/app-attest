import Foundation

extension BackendIntegrationService {
    func attest(keyID: String, _ attestation: Data) async throws {
        let (data, response) = try await session
            .data(for: .attest(
                keyID: keyID,
                attestation: attestation
            ))
    }

    func helloWorld(assertion: Data, keyID: String) async throws {
        let (data, response) = try await session
            .data(for: .helloWorld(assertion: assertion, keyID: keyID))
        guard let response = response as? HTTPURLResponse,
              response.statusCode == 200 else {
            print("-- Unexpected response: \(response)")
            throw URLError(.badServerResponse)
        }
    }
}
