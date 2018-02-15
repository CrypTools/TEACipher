// Test made using EyeJS - https://eye.js.org

const path = require('path').normalize(__testDir + "/../")

const encrypt = require(path + "encrypt.js")
const decrypt = require(path + "decrypt.js")


eye.test("Encryption", "node",
	$ => $(encrypt("Hello World!", "key")).Equal("íSjÝqTÂWÕãAa[UÄ")
)
eye.test("Decryption", "node",
	$ => $(decrypt("íSjÝqTÂWÕãAa[UÄ", "key")).Equal("Hello World!"),
	$ => $(decrypt(encrypt("attack", "pass"), "pass")).Equal("attack")
)
