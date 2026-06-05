import AttestationDecoding
import AttestationValidation
import Crypto
import Fluent
import Vapor

/// A middleware that enforces requests must provide a valid App Attest assertion.
actor ClientAttestationMiddleware: AsyncMiddleware {
    private let validator: AssertionRequestValidator

    init(appID: String, environment: AttestationEnvironment) {
        self.validator = AssertionRequestValidator(appID: appID)
        _ = environment
    }

    func respond(to request: Request,
                 chainingTo next: any AsyncResponder) async throws -> Response {
        guard let keyID = request.headers.first(name: "X-AppAttest-KeyID"),
              !keyID.isEmpty,
              let assertionToken = request.headers.bearerAuthorization?.token,
              let assertion = Data(base64Encoded: assertionToken),
              !assertion.isEmpty
        else {
            request.logger.warning("app-attest unauthorized: missing keyID header or invalid bearer assertion")
            throw Abort(.unauthorized)
        }

        let providedAssertionHash = request.headers.first(name: "X-AppAttest-AssertionHash") ?? ""
        let expectedAssertionHash = Data(SHA256.hash(data: assertion)).base64EncodedString()
        if !providedAssertionHash.isEmpty,
           providedAssertionHash != expectedAssertionHash {
            request.logger.warning(
                "app-attest unauthorized: assertion hash mismatch",
                metadata: [
                    "keyID": .string(keyID),
                    "providedAssertionHash": .string(providedAssertionHash),
                    "expectedAssertionHash": .string(expectedAssertionHash)
                ]
            )
            throw Abort(.unauthorized)
        }

        do {
            try await request.db.transaction { db in
                guard let attestedKey = try await db.query(AttestedKey.self)
                    .filter(\.$keyID, .equal, keyID)
                    .first() else {
                    request.logger.warning(
                        "app-attest unauthorized: no attested key",
                        metadata: ["keyID": .string(keyID)]
                    )
                    throw Abort(.unauthorized)
                }

                let challenges = try await db.query(IssuedChallenge.self)
                    .filter(\.$keyID, .equal, keyID)
                    .all()

                guard let twoMinutesAgo = Calendar.current.date(byAdding: .minute, value: -2, to: Date()) else {
                    request.logger.warning("app-attest unauthorized: challenge window calculation failed")
                    throw Abort(.unauthorized)
                }

                // Choose the newest fresh challenge and tolerate duplicate historical rows.
                guard let challenge = challenges
                    .filter({ ($0.createdAt ?? .distantPast) > twoMinutesAgo })
                    .max(by: { ($0.createdAt ?? .distantPast) < ($1.createdAt ?? .distantPast) })
                else {
                    request.logger.warning(
                        "app-attest unauthorized: no fresh challenge",
                        metadata: [
                            "keyID": .string(keyID),
                            "challengeCount": .stringConvertible(challenges.count)
                        ]
                    )
                    throw Abort(.unauthorized)
                }

                let expectedClientDataHash = Data(SHA256.hash(data: challenge.challenge)).base64EncodedString()
                let providedClientDataHash = request.headers.first(name: "X-AppAttest-ClientDataHash") ?? ""
                if !providedClientDataHash.isEmpty,
                   providedClientDataHash != expectedClientDataHash {
                    request.logger.warning(
                        "app-attest unauthorized: clientDataHash mismatch",
                        metadata: [
                            "keyID": .string(keyID),
                            "providedClientDataHash": .string(providedClientDataHash),
                            "expectedClientDataHash": .string(expectedClientDataHash)
                        ]
                    )
                    throw Abort(.unauthorized)
                }

                let counter: Int
                do {
                    counter = try self.validator.validate(
                        assertion: assertion,
                        challenge: challenge.challenge,
                        keyID: keyID,
                        publicKey: attestedKey.publicKey,
                        minimumCounter: attestedKey.signCount
                    )
                } catch {
                    let decoded = try? AssertionDecoder().decode(data: assertion)
                    request.logger.warning(
                        "app-attest unauthorized: assertion validation failed",
                        metadata: [
                            "keyID": .string(keyID),
                            "error": .string(String(describing: error)),
                            "assertionBytes": .stringConvertible(assertion.count),
                            "authenticatorDataBytes": .stringConvertible(decoded?.authenticatorData.rawValue.count ?? -1),
                            "signatureBytes": .stringConvertible(decoded?.signature.count ?? -1),
                            "signCount": .stringConvertible(decoded?.authenticatorData.counter ?? -1),
                            "challengeBytes": .stringConvertible(challenge.challenge.count),
                            "storedPublicKeyBytes": .stringConvertible(attestedKey.publicKey.count),
                            "expectedClientDataHash": .string(expectedClientDataHash),
                            "providedClientDataHash": .string(providedClientDataHash),
                            "expectedAssertionHash": .string(expectedAssertionHash),
                            "providedAssertionHash": .string(providedAssertionHash)
                        ]
                    )
                    throw Abort(.unauthorized)
                }

                // Consume all outstanding rows for this key and advance counter atomically.
                try await challenges.delete(force: true, on: db)
                attestedKey.signCount = counter
                try await attestedKey.save(on: db)

                request.logger.debug(
                    "app-attest authorized request",
                    metadata: [
                        "keyID": .string(keyID),
                        "counter": .stringConvertible(counter)
                    ]
                )
            }
        } catch let abort as Abort {
            throw abort
        } catch {
            request.logger.error(
                "app-attest middleware failed unexpectedly",
                metadata: ["error": .string(String(describing: error))]
            )
            throw Abort(.unauthorized)
        }

        return try await next.respond(to: request)
    }
}
