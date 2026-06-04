import AttestationDecoding
import Fluent
import Vapor

struct ChallengeRequest: Content {
    let keyID: String
}

struct AttestationRequest: Content {
    let keyID: String
    let attestation: Data
}

struct AppAttestController: RouteCollection {
    let validator: AttestationRequestValidator

    func boot(routes: RoutesBuilder) throws {
        routes.post("challenge", use: challenge)
        routes.post("verify", use: verify)
    }

    @Sendable
    func challenge(req: Request) async throws -> IssuedChallengeDTO {
        // Extract key ID
        let keyID = try req.content
            .decode(ChallengeRequest.self)
            .keyID

        // Invalidate any previous challenge for this key to keep one active challenge.
        let existingChallenges = try await req.db.query(IssuedChallenge.self)
            .filter(\.$keyID, .equal, keyID)
            .all()
        try await existingChallenges.delete(force: true, on: req.db)

        // Create challenge for attestation
        let challenge = try IssuedChallengeDTO(
            keyID: keyID
        )

        // Store challenge for validating `AttestationRequest`
        try await challenge.toModel().save(on: req.db)

        return challenge
    }

    @Sendable
    func verify(req: Request) async throws -> HTTPStatus {
        let request = try req.content.decode(AttestationRequest.self)
        let challenges = try await req.db.query(IssuedChallenge.self)
            .filter(\.$keyID, .equal, request.keyID)
            .all()

        guard let twoMinutesAgo = Calendar.current.date(byAdding: .minute, value: -2, to: Date()) else {
            return .unauthorized
        }

        // Choose the newest fresh challenge and tolerate duplicate historical rows.
        let currentChallenge = challenges
            .filter { ($0.createdAt ?? .distantPast) > twoMinutesAgo }
            .max(by: { ($0.createdAt ?? .distantPast) < ($1.createdAt ?? .distantPast) })

        guard let challenge = currentChallenge else {
            try await challenges.delete(force: true, on: req.db)
            return .unauthorized
        }

        // Validate the Attestation Object
        do {
            try await validator.validate(
                request, against: challenge.challenge
            )

            // Persist the attested public key used for verifying future assertions.
            let attestationObject = try AttestationDecoder().decode(data: request.attestation)
            let publicKey = Data(
                attestationObject.statement.certificateChain[0].publicKey.subjectPublicKeyInfoBytes
            )

            if let existing = try await req.db.query(AttestedKey.self)
                .filter(\.$keyID, .equal, request.keyID)
                .first() {
                existing.publicKey = publicKey
                existing.signCount = 0
                try await existing.save(on: req.db)
            } else {
                let key = AttestedKey(
                    keyID: request.keyID,
                    publicKey: publicKey,
                    signCount: 0
                )
                try await key.save(on: req.db)
            }
        } catch {
            return .unauthorized
        }

        // Discard all outstanding challenges for this key after verify attempt.
        try await challenges.delete(force: true, on: req.db)

        return .ok
    }
}
