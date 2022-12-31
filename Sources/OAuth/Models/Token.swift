import Foundation

public struct Token: Codable {
    public let token_type: String
    public let refresh_token: String
    public let access_token: String
    public let expires_at: Double
    public let expires_in: Int
}
