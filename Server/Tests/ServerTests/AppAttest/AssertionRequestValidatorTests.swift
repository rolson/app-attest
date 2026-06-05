import Foundation
@testable import Server
import Testing

struct AssertionRequestValidatorTests {
    @Test("Validate known-good App Attest assertion sample")
    func validatesReferenceAssertionSample() throws {
        let validator = AssertionRequestValidator(
            appID: "6MURL8TA57.de.vincent-haupert.apple-appattest-poc"
        )

        let assertion = Data(base64Encoded: "omlzaWduYXR1cmVYRjBEAiBJ6BT/QR689UKy84YyN3RDydYD9KVQ2BTRK+x1i8ezqAIgGM7BsZbSuF6TjmK6xtOFekyVyjf8akGvp5qFRGm9LTxxYXV0aGVudGljYXRvckRhdGFYJUVlEup+JpR2q5Pht5cWhVkv9z+JSsDsL9VICKCL+2yPQAAAAAE=")!
        let clientData = Data(base64Encoded: "d3VyemVscGZyb3Bm")!
        let publicKey = Data(hex: "0488c034a190aa7dbc5a061501c6542803942582198b3f1cc54673ca3b9ad20b41528267a54f5fdba0469fafb46bb6990a396bf04f94a49d4320c81c7ab240a398")

        let counter = try validator.validate(
            assertion: assertion,
            challenge: clientData,
            keyID: "YmbJO4x5nEHUvncp9zdWuVZjNBEMgJn3cdSToAXQe3M=",
            publicKey: publicKey,
            minimumCounter: 0
        )

        #expect(counter == 1)
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        self.reserveCapacity(hex.count / 2)

        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            self.append(UInt8(hex[index..<nextIndex], radix: 16)!)
            index = nextIndex
        }
    }
}
