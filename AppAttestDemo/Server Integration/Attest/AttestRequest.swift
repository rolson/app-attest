import Crypto
import Foundation

extension URLRequest {
    struct AttestRequest: Encodable {
        let keyID: String
        let attestation: Data
    }

    static func attest(
        keyID: String,
        attestation: Data
    ) throws -> URLRequest {
        var request = URLRequest(url: .attest)
        request.httpMethod = "POST"
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )

        let requestBody = AttestRequest(
            keyID: keyID,
            attestation: attestation
        )
        request.httpBody = try JSONEncoder().encode(requestBody)

        return request
    }

}

extension URL {
    static var attest: URL {
        local.appending(path: "verify")
    }
}

extension URLRequest {
    static func helloWorld(
        assertion: Data,
        keyID: String,
        clientDataHash: Data? = nil
    ) throws -> URLRequest {
        var request = URLRequest(url: .helloWorld)
        request.httpMethod = "GET"
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )

        // Send the assertion as a Bearer token expected by server middleware.
        request.setValue(
            "Bearer \(assertion.base64EncodedString())",
            forHTTPHeaderField: "Authorization"
        )
        request.setValue(keyID, forHTTPHeaderField: "X-AppAttest-KeyID")
        request.setValue(
            Data(SHA256.hash(data: assertion)).base64EncodedString(),
            forHTTPHeaderField: "X-AppAttest-AssertionHash"
        )

        if let clientDataHash {
            request.setValue(
                clientDataHash.base64EncodedString(),
                forHTTPHeaderField: "X-AppAttest-ClientDataHash"
            )
        }

        return request
    }

}

extension URL {
    static var helloWorld: URL {
        local.appending(path: "hello-world")
    }
}
