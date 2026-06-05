import AttestationValidation
import Fluent
import Vapor

private let defaultAppID = "P8HGHS7JQ8.com.appattest.demo.1"
private let appID = Environment.get("APP_ATTEST_APP_ID") ?? defaultAppID
let environment: AttestationEnvironment = .development

func routes(_ app: Application) throws {
    try app.grouped(
        ClientAttestationMiddleware(appID: appID)
    ).register(collection: HelloWorldController())

    try app.register(collection:
        AppAttestController(
            validator: AppAttestRequestValidator(
                appID: appID,
                environment: environment
            )
        )
    )
}
