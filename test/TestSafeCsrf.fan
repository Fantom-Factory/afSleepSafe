using afBounce

internal class TestSafeCsrf : SleepSafeTest {
	
	Void testCsrfHappy() {
		res := fireUp.get(`/csrf1`)
		FormInput("[name=nom1]").verifyValueEq("val1")
		res = Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom1=val1")
	}

}
