//
//  ProcyonKeyMethod.swift
//  SwiftNIOSSL
//
//  Created by Anil Jha on 9/7/21.
//

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif

public class ProcyonKeyMethod {
}

public protocol PrivateKeyMethodDelegate:AnyObject {
    func SignMe(outdata: UnsafeMutablePointer<UInt8>,
                              outlen: UnsafeMutablePointer<Int>,
                              maxout: Int,
                              signaturealgorithm: UInt16,
                              indata: UnsafePointer<UInt8>,
                              inlen: Int) -> Bool
    func decryptMe(outdata: UnsafeMutablePointer<UInt8>,
                              outlen: UnsafeMutablePointer<Int>,
                              maxout: Int,
                              indata: UnsafePointer<UInt8>,
                              inlen: Int) -> Bool

    func completeMe(outdata: UnsafeMutablePointer<UInt8>,
                              outlen: UnsafeMutablePointer<Int>,
                              maxout: Int) -> Bool
}

fileprivate weak var methodDelegate:PrivateKeyMethodDelegate?
fileprivate var method = SSL_PRIVATE_KEY_METHOD()

public extension NIOSSLContext {

    static func setPrivateKeyDelegate(delegate: PrivateKeyMethodDelegate?) {
        methodDelegate = delegate
    }
    static func setPrivateKeyMethod(context: OpaquePointer) throws {
        if methodDelegate == nil {
            return
        }
        method.sign = {
            guard let outdata = $1, let outlen = $2, let indata = $5 else {
                return ssl_private_key_failure
            }
            if let delegate = methodDelegate {
                if delegate.SignMe(outdata: outdata, outlen: outlen, maxout: $3, signaturealgorithm: $4, indata: indata, inlen: $6) {
                    return ssl_private_key_success
                }
            }
            return ssl_private_key_failure
        }
        method.decrypt = {
            guard let outdata = $1, let outlen = $2, let indata = $4 else {
                return ssl_private_key_failure
            }
            if let delegate = methodDelegate {
                if delegate.decryptMe(outdata: outdata, outlen: outlen, maxout: $3, indata:indata, inlen: $5) {
                    return ssl_private_key_success
                }
            }
            return ssl_private_key_failure
        }
        method.complete = {
            guard let outdata = $1, let outlen = $2 else {
                return ssl_private_key_failure
            }
            if let delegate = methodDelegate {
                if delegate.completeMe(outdata: outdata, outlen: outlen, maxout: $3) {
                    return ssl_private_key_success
                }
            }
            return ssl_private_key_success
        }
        
        CNIOBoringSSL_SSL_CTX_set_private_key_method(context, &method)

/*        withUnsafePointer(to: keyMethod.method) { keyPtr in
            CNIOBoringSSL_SSL_CTX_set_private_key_method(context, keyPtr)
        }
*/
        /*withUnsafePointer(to: keyMethod) { keyPtr in
            keyPtr.withMemoryRebound(to: SSL_PRIVATE_KEY_METHOD.self, capacity: 1) { ptr in
                CNIOBoringSSL_SSL_CTX_set_private_key_method(context, ptr)
            }
        }*/
    }
}
