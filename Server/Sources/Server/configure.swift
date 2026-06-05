import NIOSSL
import Fluent
import FluentSQLiteDriver
import Vapor

// configures your application
public func configure(_ app: Application) async throws {
    let database: DatabaseConfigurationFactory = app.environment == .testing
        ? .sqlite(.memory)
        : .sqlite(.file("db.sqlite"))

    app.databases.use(database, as: .sqlite)
    app.migrations.add(CreateAppInstance())
    app.migrations.add(CreateAttestedKey())
    // register routes
    try routes(app)
}
