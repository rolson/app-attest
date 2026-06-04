import AttestationDecoding
import AttestationValidation
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
            // TODO: validate the assertion using a stored challenge and public key.
            // validator.validate(assertion: assertion, challenge: challenge, keyID: keyID)
        else {
            throw Abort(.unauthorized)
        }

        return try await next.respond(to: request)
    }
}
