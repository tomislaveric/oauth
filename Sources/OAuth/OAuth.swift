import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func getAccessToken() async throws -> String?
}

public struct OAuthConfig {
    public init(authorizeUrl: String, tokenUrl: String, clientId: String, redirectUri: String, callbackURLScheme: String, clientSecret: String, scope: String) {
        self.authorizeUrl = authorizeUrl
        self.tokenUrl = tokenUrl
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackURLScheme = callbackURLScheme
        self.clientSecret = clientSecret
        self.scope = scope
    }
    
    public enum GrantType: String {
        case authorizationCode = "authorization_code"
        case refreshToken = "refresh_token"
    }
    
    public let authorizeUrl: String
    public let tokenUrl: String
    public let clientId: String
    public let redirectUri: String
    public let callbackURLScheme: String
    public let clientSecret: String
    public let responseType: String = "code"
    public let approvalPrompt: String = "auto"
    public let grantType: GrantType = .authorizationCode
    public let scope: String
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    private let httpRequest: HTTPRequest
    private let config: OAuthConfig
    private var token: Token? = nil
    
    public init(config: OAuthConfig) {
        self.config = config
        self.httpRequest = HTTPRequestImpl()
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
    
    public func getAccessToken() async throws -> String? {
        //TODO: check for expiration as well
        if let token = self.token {
            return buildBearerToken(from: token)
        } else {
            //handle refresh token
        }
       
        guard let token = try await authorize() else { return nil }
        self.token = token
        return buildBearerToken(from: token)
    }
    
    @MainActor
    private func authorize() async throws -> Token? {
        guard let url = self.buildAuthUrl(from: config) else { return nil }
        
        let authUrl = try await withCheckedThrowingContinuation({ (continuation: CheckedContinuation<URL, Error>) in
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
            })
        
        return try await getToken(from: buildAccessTokenUrl(from: authUrl))
    }
    
    private func getToken(from url: URL?) async throws -> Token? {
        guard let url = url else {
            throw OAuthError.badUrlError
        }
        let request = URLRequest(url: url)
        return try await httpRequest.post(request: request)
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
            URLQueryItem(name: "grant_type", value: OAuthConfig.GrantType.authorizationCode.rawValue)
        ]
        return components?.url
    }
    
    private func buildRefreshTokenUrl(from token: Token) -> URL? {
        var components = URLComponents(string: config.tokenUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "client_secret", value: config.clientSecret),
            URLQueryItem(name: "refresh_token", value: token.refresh_token),
            URLQueryItem(name: "grant_type", value: OAuthConfig.GrantType.refreshToken.rawValue)
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
    
    private func buildBearerToken(from token: Token) -> String {
        return "\(token.token_type) \(token.access_token)"
    }
}

enum OAuthError: Error {
    case badUrlError
}

struct Token: Decodable {
    let token_type: String
    let expires_at: Int
    let expires_in: Int
    let refresh_token: String
    let access_token: String
}
