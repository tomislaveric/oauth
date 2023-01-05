import XCTest
import WebKit
import HTTPRequest
@testable import OAuth

final class OAuthTests: XCTestCase {
    func test_shouldReturnActualToken_ifNotExpired() async throws {
        let actual: Token = Token(
            token_type: "",
            refresh_token: "123",
            access_token: "321",
            expires_at: Date().timeIntervalSince1970 + 12,
            expires_in: 12
        )
        
        let sut = OAuthImpl(config: OAuthConfig.fixture)
        let expectation = expectation(description: "Fetch access token")
        
        let result = try await sut.getAccessToken(currentToken: actual, isValid: true)
        XCTAssertEqual(result?.access_token, actual.access_token)
        expectation.fulfill()
        wait(for: [expectation], timeout: 2)
        
    }
    
//    func test_shouldReturnRefreshToken_ifExpired() async throws {
//        let config = URLSessionConfiguration.default
//        config.protocolClasses?.insert(MockURLProtocol.self, at: 0)
//        
//        let actualToken: Token = Token(
//            token_type: "",
//            refresh_token: "123",
//            access_token: "321",
//            expires_at: Date().timeIntervalSince1970 - 1,
//            expires_in: 12
//        )
//        
//        let expectedToken = Token(
//            token_type: "",
//            refresh_token: "123",
//            access_token: "321Refreshed",
//            expires_at: Date().timeIntervalSince1970 + 1,
//            expires_in: 12
//        )
//        let refreshQuery = "?client_id=&client_secret=&refresh_token=\(actualToken.refresh_token)&grant_type="
//        MockURLProtocol.mockData[refreshQuery] = try JSONEncoder().encode(expectedToken.self)
//        
//        let sut = OAuthImpl(config: OAuthConfig.fixture, request: HTTPRequestImpl(session: URLSession(configuration: config)))
//
//        let expectation = expectation(description: "Fetch refresh token")
//        let result = try await sut.getAccessToken(currentToken: actualToken, isValid: true)
//        XCTAssertEqual(result?.access_token, expectedToken.access_token)
//        expectation.fulfill()
//        wait(for: [expectation], timeout: 2)
//    }
}

extension OAuthConfig {
    static let fixture = OAuthConfig(authorizeUrl: "", tokenUrl: "", clientId: "", redirectUri: "", callbackURLScheme: "", clientSecret: "", responseType: "", approvalPrompt: "", scope: "", authorizationGrant: "", refreshGrant: "")
}
