using afIoc::Inject
using afIocEnv::IocEnv
using afIocConfig::Config
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
			private const AtomicRef		futureRef		:= AtomicRef(null)
			private const AtomicRef		keyRef			:= AtomicRef(null)
			private const AtomicRef		initVectorRef	:= AtomicRef(null)
	@Config	private const Str?			csrfPassPhrase

	private new make(|This| f) { f(this) }

	** Because generating a secure key can take a good number of seconds, to speed up BedSheet start up times,
	** we do it in the background.
	Void generateKey() {
		futureRef.val = thread.async |->| {
			
			// use the user supplied pass phrase - this lets tokens be used accross server restarts
			passPhrase	:= csrfPassPhrase ?: ""

			// need to keep the salt the same to generate the same key, so here's one I made earlier
			salt		:= Buf.fromBase64("cGEmBLnzakNWRBbfeJCzdw")

			// or generate our own random key if none supplied
			if (csrfPassPhrase == null) {
				passPhrase	= Buf.random(42).toBase64Uri
				salt		= Buf.random(16)
			}
			
		    noOfBits	:= 128
		    noOfBytes	:= noOfBits / 8
		    iterations	:= iocEnv.isDev ? 0x10 : 0x6666
		    keyBuf		:= Buf.pbk("PBKDF2WithHmacSHA256", passPhrase, salt, iterations, noOfBytes)
			keyRef.val	= keyBuf.toImmutable
			
			keySpec		:= SecretKeySpec(toBytes(keyRef.val), "AES")
			cipher		:= Cipher.getInstance("AES/CBC/PKCS5Padding")
			cipher.init(Cipher.ENCRYPT_MODE, keySpec)
			specClass	:= Class.forName("javax.crypto.spec.IvParameterSpec")
			initVector	:= ((IvParameterSpec) AlgorithmParameters#getParameterSpec.call(cipher.getParameters, specClass)).getIV
			initVectorRef.val = toBuf(initVector).toImmutable
		}
	}

	Str encode(Str msg) {
		keyBuf		:= secretKey
		keySpec		:= SecretKeySpec(toBytes(keyBuf), "AES")
		cipher		:= Cipher.getInstance("AES/CBC/PKCS5Padding")
		ivSpec		:= IvParameterSpec(toBytes(initVectorRef.val))
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
		cipherText	:= cipher.doFinal(toBytes(msg.toBuf))
		token		:= toBuf(cipherText)

		// need to embed the init vector so the token can be used across server restarts
		return token.toBase64Uri + ":" + ((Buf) initVectorRef.val).toBase64Uri
	}

	Str decode(Str cipherText) {
		split		:= cipherText.split(':')
		keyBuf		:= secretKey
		keySpec		:= SecretKeySpec(toBytes(keyBuf), "AES")
		cipher		:= Cipher.getInstance("AES/CBC/PKCS5Padding")
		ivSpec		:= IvParameterSpec(toBytes(Buf.fromBase64(split[1])))
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
		plainText	:= cipher.doFinal(toBytes(Buf.fromBase64(split[0])))
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
		if (keyRef.val == null || initVectorRef.val == null)
			((Future) futureRef.val).get(30sec)
		return keyRef.val
	}
}
