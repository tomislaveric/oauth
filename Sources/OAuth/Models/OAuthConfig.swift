import Foundation

public struct OAuthConfig {
    public init(
        authorizeUrl: String,
        tokenUrl: String,
        clientId: String,
        redirectUri: String,
        callbackURLScheme: String,
        clientSecret: String,
        responseType: String,
        approvalPrompt: String,
        scope: String,
        authorizationGrant: String,
        refreshGrant: String
    ) {
        self.authorizeUrl = authorizeUrl
        self.tokenUrl = tokenUrl
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.callbackURLScheme = callbackURLScheme
        self.clientSecret = clientSecret
        self.responseType = responseType
        self.approvalPrompt = approvalPrompt
        self.scope = scope
        self.authorizationGrant = authorizationGrant
        self.refreshGrant = refreshGrant
    }
    
    public let authorizeUrl: String
    public let tokenUrl: String
    public let clientId: String
    public let redirectUri: String
    public let callbackURLScheme: String
    public let clientSecret: String
    public let responseType: String
    public let approvalPrompt: String
    public let scope: String
    public let authorizationGrant: String
    public let refreshGrant: String
}
