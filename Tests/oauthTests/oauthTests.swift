import XCTest
@testable import oauth

final class oauthTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(oauth().text, "Hello, World!")
    }
}
