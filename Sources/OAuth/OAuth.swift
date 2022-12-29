import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func getAccessToken() async throws -> String?
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    private let request: HTTPRequest
    private let config: OAuthConfig
    private var token: TokenResponse? = nil
    
    public init(config: OAuthConfig, request: HTTPRequest = HTTPRequestImpl()) {
        self.config = config
        self.request = request
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
    private func authorize() async throws -> TokenResponse? {
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
    
    private func getToken(from url: URL?) async throws -> TokenResponse? {
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
    
    private func buildRefreshTokenUrl(from token: TokenResponse) -> URL? {
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
    
    private func buildBearerToken(from token: TokenResponse) -> String {
        return "\(token.token_type) \(token.access_token)"
    }
}

enum OAuthError: Error {
    case badUrlError
}
