import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func authorize(authUrl url: URL) async throws -> URL
    func getAccessToken<TokenType: Decodable>(currentToken: TokenType?, accessUrl: URL?) async throws -> TokenType?
    func refreshToken<TokenType: Decodable>(refreshUrl: URL) async throws -> TokenType
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    
    private let request: HTTPRequest
    private let callbackURLScheme: String
    
    public init(callbackURLScheme: String, request: HTTPRequest = HTTPRequestImpl()) {
        self.callbackURLScheme = callbackURLScheme
        self.request = request
    }
    
    public func refreshToken<TokenType: Decodable>(refreshUrl: URL) async throws -> TokenType {
        guard let response: TokenType = try await getToken(from: refreshUrl) else {
            throw OAuthError.couldNotFetchRefreshToken
        }
        return response
    }
    
    public func getAccessToken<TokenType: Decodable>(currentToken: TokenType?, accessUrl: URL?) async throws -> TokenType? {
        if let token = currentToken {
            return token
        }
        return try await getToken(from: accessUrl)
    }

    @MainActor
    public func authorize(authUrl url: URL) async throws -> URL {
        return try await withCheckedThrowingContinuation({ (continuation: CheckedContinuation<URL, Error>) in
            let authSession = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: self.callbackURLScheme) { url, error in
                    if let url = url {
                        continuation.resume(returning: url)
                    } else if let error = error {
                        continuation.resume(throwing: error)
                    }
                }
            authSession.presentationContextProvider = self
            authSession.prefersEphemeralWebBrowserSession = true
            authSession.start()
        })
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
    
    private func getToken<TokenType: Decodable>(from url: URL?) async throws -> TokenType? {
        return try await request.post(url: url, header: nil)
    }
}

enum OAuthError: Error {
    case couldNotFetchRefreshToken
}
