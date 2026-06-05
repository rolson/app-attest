@testable import Server
import XCTVapor
import Testing

@Suite("App route authorization tests", .serialized)
struct AppTests {
    private func withApp(_ test: (Application) async throws -> Void) async throws {
        let app = try await Application.make(.testing)
        var capturedError: Error?

        do {
            try await configure(app)
            try await test(app)
        } catch {
            capturedError = error
        }

        try await app.asyncShutdown()

        if let capturedError {
            throw capturedError
        }
    }

    private func assertHelloWorldUnauthorized(
        in app: Application,
        headers: HTTPHeaders = [:]
    ) async throws {
        try await app.test(.GET, "hello-world", headers: headers) { res async in
            #expect(res.status == .unauthorized)
        }
    }

    @Test("GET /hello-world returns unauthorized without required attestation headers")
    func helloWorldRejectsRequestsMissingAttestationHeaders() async throws {
        try await withApp { app in
            let headerVariants: [HTTPHeaders] = [
                [:],
                ["Authorization": "Bearer test"],
            ]

            for headers in headerVariants {
                try await assertHelloWorldUnauthorized(in: app, headers: headers)
            }
        }
    }
}
