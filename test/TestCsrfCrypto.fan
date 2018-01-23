using afIoc

internal class TestCsrfCrypto : SleepSafeTest {

	// Randomly generated keys CAN NOT be used across server re-starts
	Void testRandomKey() {

		fireUp
		crypto	:= (CsrfCrypto) server.serviceById(CsrfCrypto#.qname)
		cipher	:= crypto.encode("Hello Mum!")

		// test the basics!
		verifyEq(crypto.decode(cipher), "Hello Mum!")
		
		// restart
		server.shutdown
		fireUp
		crypto	= (CsrfCrypto) server.serviceById(CsrfCrypto#.qname)

		// attempt re-decode the token
		verifyErr(Err#) |->| {
			verifyEq(crypto.decode(cipher), "Hello Mum!")
		}
	}

	// User keys CAN be re-used across server re-starts
	Void testUserKey() {

		fireUp([,], ["afSleepSafe.csrfPassPhrase":"wotever"])
		crypto	:= (CsrfCrypto) server.serviceById(CsrfCrypto#.qname)
		cipher	:= crypto.encode("Hello Mum!")

		// test the basics!
		verifyEq(crypto.decode(cipher), "Hello Mum!")
		
		// restart
		server.shutdown
		fireUp([,], ["afSleepSafe.csrfPassPhrase":"wotever"])
		crypto	= (CsrfCrypto) server.serviceById(CsrfCrypto#.qname)

		// attempt re-decode the token
		verifyEq(crypto.decode(cipher), "Hello Mum!")
		
		// make sure we're not cheating - change the passcode!
		server.shutdown
		fireUp([,], ["afSleepSafe.csrfPassPhrase":"wotever v2"])
		crypto	= (CsrfCrypto) server.serviceById(CsrfCrypto#.qname)
		verifyErr(Err#) |->| {
			verifyEq(crypto.decode(cipher), "Hello Mum!")
		}
	}
}
