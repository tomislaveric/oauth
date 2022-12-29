import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func authorize() async throws -> String?
}

public struct OAuthConfig {
    public init(authorizeUrl: String, tokenUrl: String, clientId: String, redirectUri: String, callbackURLScheme: String, clientSecret: String) {
        self.authorizeUrl = authorizeUrl
        self.tokenUrl = tokenUrl
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackURLScheme = callbackURLScheme
        self.clientSecret = clientSecret
    }
    
    public let authorizeUrl: String
    public let tokenUrl: String
    public let clientId: String
    public let redirectUri: String
    public let callbackURLScheme: String
    public let clientSecret: String
    public let responseType: String = "code"
    public let approvalPrompt: String = "auto"
    public let grantType: String = "authorization_code"
    public let scope: String = "activity:write,read"
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    private let httpRequest: HTTPRequest
    private let config: OAuthConfig
    
    public init(config: OAuthConfig, session: URLSession? = nil) {
        self.config = config
        if let session = session {
            self.httpRequest = HTTPRequestImpl(session: session)
        } else {
            self.httpRequest = HTTPRequestImpl()
        }
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
    
    @MainActor
    public func authorize() async throws -> String? {
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
        
        guard let token = try await getToken(from: authUrl) else { return nil }
        return "\(token.token_type) \(token.access_token)"
    }
    
    private func getToken(from authUrl: URL) async throws -> Token? {
        guard let tokenUrl = buildTokenUrl(from: authUrl) else { return nil }
        let request = URLRequest(url: tokenUrl)
        return try await httpRequest.post(request: request)
    }
    
    private func buildTokenUrl(from authResponse: URL) -> URL? {
        guard let authComponents = URLComponents(url: authResponse, resolvingAgainstBaseURL: true) else { return nil }
        let authToken = authComponents.queryItems?.first(where: { $0.name == self.config.responseType })?.value
        
        var components = URLComponents(string: config.tokenUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "client_secret", value: config.clientSecret),
            URLQueryItem(name: "code", value: authToken),
            URLQueryItem(name: "grant_type", value: config.grantType)
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

struct Token: Decodable {
    let token_type: String
    let expires_at: Int
    let expires_in: Int
    let refresh_token: String
    let access_token: String
}
