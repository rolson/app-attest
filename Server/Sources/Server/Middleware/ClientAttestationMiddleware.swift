import AttestationDecoding
import AttestationValidation
import Fluent
import Vapor

/// A middleware that enforces requests must provide an Attestation Object from Apple's DeviceCheck framework.
actor ClientAttestationMiddleware: AsyncMiddleware {
    private let decoder = AttestationDecoder()
    private let validator: AttestationValidator

    init(appID: String, environment: AttestationEnvironment) {
        validator = AttestationValidator(
            appID: appID,
            environment: environment
        )
    }

    func respond(to request: Request,
                 chainingTo next: any AsyncResponder) async throws -> Response {
        guard let keyID = request.headers.first(name: "X-AppAttest-KeyID"),
              !keyID.isEmpty,
              let assertionToken = request.headers.bearerAuthorization?.token,
              let assertion = Data(base64Encoded: assertionToken),
              !assertion.isEmpty
        else {
            throw Abort(.unauthorized)
        }

        // Require a single, fresh challenge per key and consume it to prevent replay.
        let challenges = try await request.db.query(IssuedChallenge.self)
            .filter(\.$keyID, .equal, keyID)
            .all()

        try await challenges.delete(force: true, on: request.db)

        guard challenges.count == 1,
              let challenge = challenges.first,
              let twoMinutesAgo = Calendar.current.date(byAdding: .minute, value: -2, to: .now),
              let creationDate = challenge.createdAt,
              creationDate > twoMinutesAgo
        else {
            throw Abort(.unauthorized)
        }

        // TODO: validate the assertion using the consumed challenge and stored key material.
        // try await validator.validate(assertion: assertion, challenge: challenge.challenge, keyID: keyID)

        return try await next.respond(to: request)
    }
}
