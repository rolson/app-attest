@testable import Server
import XCTVapor
import Testing

@Suite("App Tests with DB", .serialized)
struct AppTests {
    private func withApp(_ test: (Application) async throws -> Void) async throws {
        let app = try await Application.make(.testing)
        do {
            try await configure(app)
            try await test(app)
        } catch {
            try await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }

    @Test("Test Hello World Route requires attestation headers")
    func helloWorldRequiresAssertion() async throws {
        try await withApp { app in
            try await app.test(.GET, "hello-world", headers: ["Authorization": "Bearer test"]) { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test("Test Hello World Route without Assertion")
    func helloWorldUnauthorised() async throws {
        try await withApp { app in
            try await app.test(.GET, "hello-world") { res async in
                #expect(res.status == .unauthorized)
            }
        }
    }
}
