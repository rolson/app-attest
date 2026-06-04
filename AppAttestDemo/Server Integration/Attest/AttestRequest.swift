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
    static func helloWorld() throws -> URLRequest {
        var request = URLRequest(url: .helloWorld)
        request.httpMethod = "GET"
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        return request
    }

}

extension URL {
    static var helloWorld: URL {
        local.appending(path: "hello-world")
    }
}
