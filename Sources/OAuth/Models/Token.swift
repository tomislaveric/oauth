import Foundation

struct TokenResponse: Decodable {
    let token_type: String
    let expires_at: Int
    let expires_in: Int
    let refresh_token: String
    let access_token: String
}

struct Token: Codable {
    let expiresAt: Double
    let refreshToken: String
    let accessToken: String
}
