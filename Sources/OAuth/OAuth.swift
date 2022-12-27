import Foundation
import HTTPRequest

public protocol OAuth {
    func authorize() async throws
}

public struct OAuthImpl {
    private let httpRequest: HTTPRequest
    
    public init(httpRequest: HTTPRequest = HTTPRequestImpl()) {
        self.httpRequest = httpRequest
    }
}
