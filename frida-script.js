var SSL_VERIFY_NONE = 0;	
var func = Module.findExportByName("xvclient", "SSL_set_verify")

var SSL_set_verify = new NativeFunction(
	func,
	'void', ['pointer', 'int', 'pointer']
);


var our_callback = new NativeCallback(function (ssl, x509_ctx){
	console.log("hooked")
	return SSL_VERIFY_NONE
},'int',['int','pointer']);

Interceptor.replace(func, new NativeCallback(function(ssl, mode, callback) {
	SSL_set_verify(ssl, 0, our_callback);
}, 'void', ['pointer', 'int', 'pointer']));


var encrypt_func = Module.findExportByName("xvclient", "_ZNK2xc6Crypto5Pkcs79Encryptor7EncryptERKNSt3__16vectorIhNS3_9allocatorIhEEEE")

Interceptor.attach(encrypt_func, {
	onEnter: function(args) {
		var data_length = args[1].add(8).readPointer().toInt32()-args[1].readPointer().toInt32()
		console.log(hexdump(args[1].readPointer(), {length:data_length}))
	}
})

var import_cert_func = Module.findExportByName("xvclient", "_ZN2xc6Crypto11CertificateC2EPKhm")

Interceptor.attach(import_cert_func, {
	onEnter: function(args) {
		console.log(hexdump(args[1], {length:args[2].toInt32()}))
	}
})

var hmac_func = Module.findExportByName("xvclient", "_ZN2xc6Crypto4Hmac4Sha1EPKhmS3_m")

Interceptor.attach(hmac_func, {
	onEnter: function(args) {
		console.log("Data:")
		console.log(hexdump(args[0], {length:args[1].toInt32()}))
		
		console.log("Key:")
		console.log(hexdump(args[2], {length:args[3].toInt32()}))
	}


})
