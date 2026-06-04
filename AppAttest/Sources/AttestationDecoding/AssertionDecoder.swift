import Foundation
import SwiftCBOR

public struct AssertionDecoder {
    let decoder: CodableCBORDecoder

    public init(decoder: CodableCBORDecoder = CodableCBORDecoder()) {
        self.decoder = decoder
    }

    public func decode(data: Data) throws -> AssertionObject {
        try decoder.decode(AssertionObject.self, from: data)
    }
}
