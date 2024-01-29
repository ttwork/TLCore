// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation
import TronCore

/// Manages directories of key and wallet files and presents them as accounts.
public final class KeyStore {
    /// The key file directory.
    public let keyDirectory: URL

    /// Dictionary of accounts by address.
    private var accountsByAddress = [Address: Account]()

    /// Dictionary of keys by address.
    private var keysByAddress = [Address: KeystoreKey]()

    /// Creates a `KeyStore` for the given directory.
    public init(keyDirectory: URL) throws {
        self.keyDirectory = keyDirectory
        try load()
    }

    private func load() throws {
        let fileManager = FileManager.default
        try? fileManager.createDirectory(at: keyDirectory, withIntermediateDirectories: true, attributes: nil)

        let accountURLs = try fileManager.contentsOfDirectory(at: keyDirectory, includingPropertiesForKeys: [], options: [.skipsHiddenFiles])
        for url in accountURLs {
            do {
                let key = try KeystoreKey(contentsOf: url)
                keysByAddress[key.address] = key
                let account = Account(address: key.address, type: key.type, url: url)
                accountsByAddress[key.address] = account
            } catch {
                // Ignore invalid keys
            }
        }
    }

    /// List of accounts.
    public var accounts: [Account] {
        return Array(accountsByAddress.values)
    }

    /// Retrieves an account for the given address, if it exists.
    public func account(for address: Address) -> Account? {
        return accountsByAddress[address]
    }

    /// Retrieves a key for the given address, if it exists.
    public func key(for address: Address) -> KeystoreKey? {
        return keysByAddress[address]
    }

    /// Creates a new account.
    public func createAccount(password: String, type: AccountType) throws -> Account {
        let key = try KeystoreKey(password: password, type: type)
        keysByAddress[key.address] = key

        let url = makeAccountURL(for: key.address)
        let account = Account(address: key.address, type: type, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[key.address] = account
        return account
    }
    
    public func addAccount(account: Account) throws {
        try save(account: account, in: keyDirectory)
        accountsByAddress[account.address] = account
    }
    
    public func addKey(key: KeystoreKey) throws {
        keysByAddress[key.address] = key
    }

    /// Imports an encrypted JSON key.
    ///
    /// - Parameters:
    ///   - key: key to import
    ///   - password: key password
    ///   - newPassword: password to use for the imported key
    /// - Returns: new account
    public func `import`(json: Data, password: String, newPassword: String) throws -> Account {
        let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
        if self.account(for: key.address) != nil {
            throw Error.accountAlreadyExists
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey = try KeystoreKey(password: newPassword, key: privateKey)
        keysByAddress[newKey.address] = newKey

        let url = makeAccountURL(for: key.address)
        let account = Account(address: newKey.address, type: key.type, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[newKey.address] = account

        return account
    }

    /// Imports a wallet.
    ///
    /// - Parameters:
    ///   - mnemonic: wallet's mnemonic phrase
    ///   - passphrase: wallet's password
    ///   - derivationPath: wallet's derivation path
    ///   - encryptPassword: password to use for encrypting
    /// - Returns: new account
    public func `import`(mnemonic: String, passphrase: String = "", derivationPath: String = Wallet.defaultPath, encryptPassword: String) throws -> Account {
        if !Mnemonic.isValid(mnemonic) {
            throw Error.invalidMnemonic
        }

        let wallet = Wallet(mnemonic: mnemonic, passphrase: passphrase, path: derivationPath)
        let pubKey = wallet.getKey(at: 0).publicKey
        let address = KeystoreKey.decodeAddress(from: pubKey)
        if self.account(for: address) != nil {
            throw Error.accountAlreadyExists
        }

        let newKey = try KeystoreKey(password: encryptPassword, mnemonic: mnemonic, passphrase: passphrase, derivationPath: derivationPath)
        keysByAddress[newKey.address] = newKey

        let url = makeAccountURL(for: address)
        let account = Account(address: address, type: .hierarchicalDeterministicWallet, url: url)
        try save(account: account, in: keyDirectory)
        accountsByAddress[newKey.address] = account

        return account
    }

    /// Exports an account as JSON data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    ///   - newPassword: password to use for exported key
    /// - Returns: encrypted JSON key
    public func export(account: Account, password: String, newPassword: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey: KeystoreKey
        switch key.type {
        case .encryptedKey:
            newKey = try KeystoreKey(password: newPassword, key: privateKey)
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            newKey = try KeystoreKey(password: newPassword, mnemonic: string, passphrase: key.passphrase, derivationPath: key.derivationPath)
        }
        return try JSONEncoder().encode(newKey)
    }

    /// Exports an account as private key data.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    /// - Returns: private key data
    public func exportPrivateKey(account: Account, password: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        switch key.type {
        case .encryptedKey:
            return privateKey
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            return Wallet(mnemonic: string, passphrase: key.passphrase, path: key.derivationPath).getKey(at: 0).privateKey
        }
    }
    
    /// Exports a account as a mnemonic phrase.
    ///
    /// - Parameters:
    ///   - account: account to export
    ///   - password: account password
    /// - Returns: mnemonic phrase
    /// - Throws: `EncryptError.invalidMnemonic` if the account is not an HD wallet.
    public func exportMnemonic(account: Account, password: String) throws -> String {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }
        var data = try key.decrypt(password: password)
        defer {
            data.resetBytes(in: 0 ..< data.count)
        }
        
        switch key.type {
        case .encryptedKey:
            throw EncryptError.invalidMnemonic
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: data, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            if string.hasSuffix("\0") {
                return String(string.dropLast())
            } else {
                return string
            }
        }
    }

    /// Updates the password of an existing account.
    ///
    /// - Parameters:
    ///   - account: account to update
    ///   - password: current password
    ///   - newPassword: new password
    public func update(account: Account, password: String, newPassword: String, derivationPath: String = Wallet.defaultPath) throws {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }

        var privateKey = try key.decrypt(password: password)
        defer {
            privateKey.resetBytes(in: 0..<privateKey.count)
        }

        let newKey: KeystoreKey
        switch key.type {
        case .encryptedKey:
            newKey = try KeystoreKey(password: newPassword, key: privateKey)
        case .hierarchicalDeterministicWallet:
            guard let string = String(data: privateKey, encoding: .ascii) else {
                throw EncryptError.invalidMnemonic
            }
            newKey = try KeystoreKey(password: newPassword, mnemonic: string, passphrase: key.passphrase, derivationPath: derivationPath)
        }
        keysByAddress[newKey.address] = newKey
        try save(key: newKey, to: account.url)
    }

    /// Deletes an account including its key if the password is correct.
    public func delete(account: Account, password: String) throws {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }

        keysByAddress[account.address] = nil
        accountsByAddress[account.address] = nil
        try FileManager.default.removeItem(at: account.url)
    }

    /// Calculates a ECDSA signature for the give hash.
    ///
    /// - Parameters:
    ///   - data: hash to sign
    ///   - account: account to use for signing
    ///   - password: account password
    /// - Returns: signature
    /// - Throws: `DecryptError`, `Secp256k1Error`, or `KeyStore.Error`
    public func signHash(_ data: Data, account: Account, password: String) throws -> Data {
        guard let key = keysByAddress[account.address] else {
            throw KeyStore.Error.accountNotFound
        }
        return try key.sign(hash: data, password: password)
    }

    /// Signs an array of hashes with the given password.
    ///
    /// - Parameters:
    ///   - hashes: array of hashes to sign
    ///   - account: account to use for signing
    ///   - password: key password
    /// - Returns: array of signatures
    /// - Throws: `DecryptError` or `Secp256k1Error` or `KeyStore.Error`
    public func signHashes(_ data: [Data], account: Account, password: String) throws -> [Data] {
        guard let key = keysByAddress[account.address] else {
            throw KeyStore.Error.accountNotFound
        }
        return try key.signHashes(data, password: password)
    }

    // MARK: Helpers

    private func makeAccountURL(for address: Address) -> URL {
        return keyDirectory.appendingPathComponent(generateFileName(address: address))
    }

    /// Saves the account to the given directory.
    private func save(account: Account, in directory: URL) throws {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }
        try save(key: key, to: account.url)
    }

    /// Generates a unique file name for an address.
    func generateFileName(address: Address, date: Date = Date(), timeZone: TimeZone = .current) -> String {
        // keyFileName implements the naming convention for keyfiles:
        // UTC--<created_at UTC ISO8601>-<address hex>
        return "UTC--\(filenameTimestamp(for: date, in: timeZone))--\(address.data.hexString)"
    }

    private func filenameTimestamp(for date: Date, in timeZone: TimeZone = .current) -> String {
        var tz = ""
        let offset = timeZone.secondsFromGMT()
        if offset == 0 {
            tz = "Z"
        } else {
            tz = String(format: "%03d00", offset/60)
        }

        let components = Calendar(identifier: .iso8601).dateComponents(in: timeZone, from: date)
        return String(format: "%04d-%02d-%02dT%02d-%02d-%02d.%09d%@", components.year!, components.month!, components.day!, components.hour!, components.minute!, components.second!, components.nanosecond!, tz)
    }

    private func save(key: KeystoreKey, to url: URL) throws {
        let json = try JSONEncoder().encode(key)
        try json.write(to: url, options: [.atomicWrite])
    }
}

extension KeyStore {
    public func checkingAccountAlreadyExists(json: Data, password: String, newPassword: String) throws -> Bool {
        let key = try JSONDecoder().decode(KeystoreKey.self, from: json)
        if self.account(for: key.address) != nil {
            throw Error.accountAlreadyExists
        }
        return false
    }

    public func checkingAccountAlreadyExists(mnemonic: String, passphrase: String = "", derivationPath: String = Wallet.defaultPath, encryptPassword: String) throws -> Bool {
        if !Mnemonic.isValid(mnemonic) {
            throw Error.invalidMnemonic
        }
        
        let wallet = Wallet(mnemonic: mnemonic, passphrase: passphrase, path: derivationPath)
        let pubKey = wallet.getKey(at: 0).publicKey
        let address = KeystoreKey.decodeAddress(from: pubKey)
        if self.account(for: address) != nil {
            throw Error.accountAlreadyExists
        }
        return false
    }
    
    /// Generate an address with mnemonic derivationPath.
    public func generateWalletAddress(derivationPath:String = Wallet.defaultPath,mnemonic:String,password:String = "") -> Address{
        let wallet = Wallet(mnemonic: mnemonic, passphrase: password, path: derivationPath)
        let pubKey = wallet.getKey(at: 0).publicKey
        return KeystoreKey.decodeAddress(from: pubKey)
    }
    
    /// get an path with account.
    public func generateWalletPath(account: Account) throws -> String {
        guard let key = keysByAddress[account.address] else {
            throw DecryptError.missingAccountKey
        }
        return key.derivationPath
    }
}
