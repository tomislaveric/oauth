import Foundation
import AuthenticationServices
import HTTPRequest

public protocol OAuth {
    func getAccessToken() async throws -> String?
}

public class OAuthImpl: NSObject, OAuth, ASWebAuthenticationPresentationContextProviding {
    private let storeName = Bundle.main.bundleIdentifier ?? "Stravatar oAuthToken"
    private let request: HTTPRequest
    private let config: OAuthConfig
    private let secureStorage: KeychainStorage
    
    private func getSaved(token name: String) -> Token? {
        do {
            return try secureStorage.read(name: name)
        } catch {
            return nil
        }
    }
    
    private func save(response: TokenResponse) throws {
        let token = Token(expiresAt: Date().addingTimeInterval(TimeInterval(response.expires_in)).timeIntervalSince1970, refreshToken: response.refresh_token, accessToken: response.access_token)
        try secureStorage.save(name: storeName, object: token)
    }
    
    public init(config: OAuthConfig, request: HTTPRequest = HTTPRequestImpl(), secureStorage: KeychainStorage = KeychainStorageImpl()) {
        self.config = config
        self.request = request
        self.secureStorage = secureStorage
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return ASPresentationAnchor()
    }
    
    public func getAccessToken() async throws -> String? {
        if let token = getSaved(token: storeName), token.expiresAt > Date().timeIntervalSince1970 {
            return buildBearerToken(from: token.accessToken)
        } else if let token = getSaved(token: storeName), let refreshToken = try await getToken(from: buildRefreshTokenUrl(from: token)) {
            try save(response: refreshToken)
            return buildBearerToken(from: refreshToken.access_token)
        } else {
            guard let token = try await authorize() else { return nil }
            try save(response: token)
            return buildBearerToken(from: token.access_token)
        }
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
    
    private func buildRefreshTokenUrl(from token: Token) -> URL? {
        var components = URLComponents(string: config.tokenUrl)
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "client_secret", value: config.clientSecret),
            URLQueryItem(name: "refresh_token", value: token.refreshToken),
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
    
    private func buildBearerToken(from token: String) -> String {
        return "Bearer \(token)"
    }
}

enum OAuthError: Error {
    case badUrlError
}

public protocol KeychainStorage {
    func save<Object: Encodable>(name: String, object: Object) throws
    func read<Object: Decodable>(name: String) throws -> Object?
}

public class KeychainStorageImpl: KeychainStorage {
    private let userDefaults: UserDefaults
    
    public init(userDefaults: UserDefaults = UserDefaults.standard) {
        self.userDefaults = userDefaults
    }

    public func read<Object: Decodable>(name: String) throws -> Object? {
        
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: name,
            kSecReturnAttributes: true,
            kSecReturnData: true,
        ] as CFDictionary
       
        var ref: AnyObject?
        SecItemCopyMatching(query, &ref)
        guard let dictionary = ref as? NSDictionary else { return nil }
        guard let result = dictionary[kSecValueData] as? Data else { return nil }
        return try JSONDecoder().decode(Object.self, from: result)
    }
    
    public func save<Object: Encodable>(name: String, object: Object) throws {
 
        let objectData = try JSONEncoder().encode(object)
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: name,
            kSecValueData: objectData
        ] as CFDictionary
        Task {
            SecItemAdd(query as CFDictionary, nil)
        }
    }
}

enum KeychainError: Error {
    case unhandledError(status: OSStatus)
}
