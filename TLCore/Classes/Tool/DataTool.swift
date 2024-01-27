
import Foundation

public extension Data {
    var hex: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    var hexEncoded: String {
        return "0x" + self.hex
    }
    
    func toString() -> String? {
        return String(data: self, encoding: .utf8)
    }
    
    var addressString: String {
        return String(base58CheckEncoding: self)
    }
}
