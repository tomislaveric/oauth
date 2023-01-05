import XCTest
import WebKit
import HTTPRequest
@testable import OAuth

final class OAuthTests: XCTestCase {
    struct MockToken: Codable, Equatable {
        let access_token: String?
        let refresh_token: String?
    }
    func test_getAccessToken_shouldReturnToken_ifTokenExists() async throws {
        
        let config = URLSessionConfiguration.default
        config.protocolClasses?.insert(MockURLProtocol.self, at: 0)
        let expected = MockToken(access_token: "123", refresh_token: nil)
        MockURLProtocol.mockData["/accessToken"] = try JSONEncoder().encode(expected.self)
        
        let sut = OAuthImpl(callbackURLScheme: "", request: HTTPRequestImpl(session: URLSession(configuration: config)))
        let result: MockToken = try await sut.getAccessToken(currentToken: nil, accessUrl: XCTUnwrap(URL(string: "/accessToken")))
        
        let expectation = expectation(description: "Fetch access token")
        XCTAssertEqual(result, expected)
        expectation.fulfill()
        wait(for: [expectation], timeout: 1)
    }
    func test_getAccessToken_shouldReturn_DecodedToken() async throws {
        let expected = MockToken(access_token: "123", refresh_token: nil)
        
        let sut = OAuthImpl(callbackURLScheme: "")
        let result: MockToken = try await sut.getAccessToken(currentToken: expected, accessUrl: nil)
        
        let expectation = expectation(description: "Fetch access token")
        XCTAssertEqual(result, expected)
        expectation.fulfill()
        wait(for: [expectation], timeout: 1)
    }
    
    func test_refreshToken_shouldReturnRefreshToken() async throws {
        
        let config = URLSessionConfiguration.default
        config.protocolClasses?.insert(MockURLProtocol.self, at: 0)
        let expected = MockToken(access_token: nil, refresh_token: "321")
        MockURLProtocol.mockData["/refreshToken"] = try JSONEncoder().encode(expected.self)
        
        let sut = OAuthImpl(callbackURLScheme: "", request: HTTPRequestImpl(session: URLSession(configuration: config)))
        let result: MockToken = try await sut.getAccessToken(currentToken: nil, accessUrl: XCTUnwrap(URL(string: "/refreshToken")))
        
        let expectation = expectation(description: "Fetch access token")
        XCTAssertEqual(result, expected)
        expectation.fulfill()
        wait(for: [expectation], timeout: 1)
    }
}
