using afBounce

internal class TestSafeCsrf : SleepSafeTest {
	
	Void testCsrfHappy() {
		res := fireUp.get(`/csrfHappy`)
		FormInput("[name=nom1]").verifyValueEq("val1")
		res = Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom1=val1")
	}

	Void testCsrfNotFound() {
		res := fireUp.get(`/csrfNotFound`)
		FormInput("[name=nom2]").verifyValueEq("val2")
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Form does not contain '_csrfBuster' key")
	}

}
