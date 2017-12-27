using afIoc::Inject
using afIocEnv::IocEnv
using afConcurrent::Synchronized
using concurrent::Future
using concurrent::AtomicRef
using [java] fanx.interop::Interop
using [java] fanx.interop::ByteArray
using [java] java.lang::Class
using [java] java.nio::ByteBuffer
using [java] java.security::AlgorithmParameters
using [java] javax.crypto::Cipher
using [java] javax.crypto.spec::IvParameterSpec
using [java] javax.crypto.spec::SecretKeySpec

internal const class CsrfCrypto {
	
	@Inject { id="csrfKeyGen" }
			private const Synchronized	thread
	@Inject	private const IocEnv		iocEnv
			private const AtomicRef		futureRef	:= AtomicRef(null)
			private const AtomicRef		keyRef		:= AtomicRef(null)

	private new make(|This| f) { f(this) }

	** Because generating a secure key can take a good number of seconds, to speed up BedSheet start up times,
	** we do it in the background.
	Void generateKey() {
		futureRef.val = thread.async |->Buf| {
			passPhrase	:= "Fanny the Fantom -> Escape the Mainframe!"
			salt		:= Buf.random(16)
		    noOfBits	:= 128
		    noOfBytes	:= noOfBits / 8
		    iterations	:= iocEnv.isDev ? 0x10 : 0x10000
		    return Buf.pbk("PBKDF2WithHmacSHA256", passPhrase, salt, iterations, noOfBytes).toImmutable
		}
	}
	
	Str encode(Str msg) {
		keyBuf		:= secretKey
		keySpec	:= SecretKeySpec(toBytes(keyBuf), "AES")
		cipher	:= Cipher.getInstance("AES/CBC/PKCS5Padding")
		cipher.init(Cipher.ENCRYPT_MODE, keySpec)

		// getParameterSpec() has some knarly Java generics which I can't figure out how to create in Fantom : "<T extends AlgorithmParameterSpec>"
		// Note, java.lang.Class.asSubclass() does seem to work - maybe 'cos Fantom then assigns to a general 'Class' obj
		// Anyway, just invoke it via reflection and all is okay
		specClass	:= Class.forName("javax.crypto.spec.IvParameterSpec")
		initVector	:= ((IvParameterSpec) AlgorithmParameters#getParameterSpec.call(cipher.getParameters, specClass)).getIV
		cipherText	:= cipher.doFinal(toBytes(msg.toBuf))

		// note the initVector is the same for repeated calls to getParameterSpec() but different for each instance of Cipher
		return toBuf(initVector).toBase64Uri + toBuf(cipherText).toBase64Uri
	}

	Str decode(Str encoded) {
		initSize	:= 22
		keyBuf		:= secretKey
		initVector	:= encoded[0..<initSize]
		cipherText	:= encoded[initSize..-1]
		keySpec		:= SecretKeySpec(toBytes(keyBuf), "AES")
		cipher		:= Cipher.getInstance("AES/CBC/PKCS5Padding")
		ivSpec		:= IvParameterSpec(toBytes(Buf.fromBase64(initVector)))
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
		plainText	:= cipher.doFinal(toBytes(Buf.fromBase64(cipherText)))

		return toBuf(plainText).readAllStr.trim
	}

	private static ByteArray toBytes(Buf buf) {
		Interop.toJava(buf).array
	}

	private static Buf toBuf(ByteArray array) {
		// we can't base64 a NioBuf, so copy the contents to a standard Fantom MemBuf
		Buf().writeBuf(Interop.toFan(ByteBuffer.wrap(array))).flip
	}

	** Returns the secret key. Blocks if it hasn't been generated yet.
	private Buf secretKey() {
		if (keyRef.val != null)
			return keyRef.val
		keyRef.val = ((Future) futureRef.val).get(30sec)
		return keyRef.val
	}
}
