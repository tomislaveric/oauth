import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func getAccessToken(currentToken: Token?) async throws -> Token?
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    private let storeName = Bundle.main.bundleIdentifier ?? "Stravatar oAuthToken"
    private let request: HTTPRequest
    private let config: OAuthConfig
    
    public init(config: OAuthConfig, request: HTTPRequest = HTTPRequestImpl()) {
        self.config = config
        self.request = request
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
    
    public func getAccessToken(currentToken: Token?) async throws -> Token? {
        if let token = currentToken, isValid(token: token) {
            return token
        } else if let token = currentToken, let refreshToken = try await getToken(from: buildRefreshTokenUrl(from: token)) {
            return try await refresh(token: refreshToken)
        } else {
            guard let token = try await authorize() else { return nil }
            return token
        }
    }

    private func refresh(token: Token) async throws -> Token? {
        try await getToken(from: buildRefreshTokenUrl(from: token))
    }
    
    @MainActor
    private func authorize() async throws -> Token? {
        guard let url = self.buildAuthUrl(from: config) else { return nil }
        return try await getToken(from: buildAccessTokenUrl(from: try await withCheckedThrowingContinuation({ (continuation: CheckedContinuation<URL, Error>) in
            let authSession = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: self.config.callbackURLScheme) { url, error in
                    if let url = url {
                        continuation.resume(returning: url)
                    } else if let error = error {
                        continuation.resume(throwing: error)
                    }
                }
            authSession.presentationContextProvider = self
            authSession.prefersEphemeralWebBrowserSession = true
            authSession.start()
        })))
    }
    
    private func isValid(token: Token) -> Bool {
        return Date().timeIntervalSince1970 < token.expires_at
    }
        
    private func getToken(from url: URL?) async throws -> Token? {
        guard let url = url else {
            throw OAuthError.badUrlError
        }
        let urlRequest = URLRequest(url: url)
        return try await request.post(request: urlRequest)
    }
    
    private func buildAccessTokenUrl(from authResponse: URL) -> URL? {
        guard let authComponents = URLComponents(url: authResponse, resolvingAgainstBaseURL: true) else { return nil }
        let authToken = authComponents.queryItems?.first(where: { $0.name == self.config.responseType })?.value
        
        var components = URLComponents(string: config.tokenUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "client_secret", value: config.clientSecret),
            URLQueryItem(name: "code", value: authToken),
            URLQueryItem(name: "scope", value: config.scope),
            URLQueryItem(name: "grant_type", value: config.authorizationGrant)
        ]
        return components?.url
    }
    
    private func buildRefreshTokenUrl(from token: Token) -> URL? {
        var components = URLComponents(string: config.tokenUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "client_secret", value: config.clientSecret),
            URLQueryItem(name: "refresh_token", value: token.refresh_token),
            URLQueryItem(name: "grant_type", value: config.refreshGrant)
        ]
        return components?.url
    }
    
    private func buildAuthUrl(from config: OAuthConfig) -> URL? {
        var components = URLComponents(string: config.authorizeUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectUri),
            URLQueryItem(name: "response_type", value: config.responseType),
            URLQueryItem(name: "scope", value: config.scope)
        ]
        return components?.url
    }
}

enum OAuthError: Error {
    case badUrlError
}
