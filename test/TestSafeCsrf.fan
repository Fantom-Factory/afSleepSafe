using afBounce
using afIoc::Contribute
using afIoc::Configuration
using concurrent::Actor

internal class TestSafeCsrf : SleepSafeTest {
	
	Void testCsrfHappy() {
		fireUp
		client.get(`/csrfHappy`)
		FormInput("[name=nom]").verifyValueEq("val1")
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
	}

	Void testCsrfNoFormData() {
		fireUp
		client.get(`/csrfNoForm`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - No form data")
	}

	Void testCsrfNotFound() {
		fireUp
		client.get(`/csrfNotFound`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Form does not contain '_csrfToken' key")
	}

	Void testCsrfInvalid() {
		fireUp
		client.get(`/csrfInvalid`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	Void testCsrfTokenTimeout() {
		fireUp(["afSleepSafe.csrfTimeoutResolution":null, "afSleepSafe.csrfTokenTimeout":"20ms"])
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		Actor.sleep(30ms)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str[0..<-6], "403 - Suspected CSRF attack - Token exceeds 20ms timeout")
	}

	Void testCsrfCustomTokenName() {
		fireUp(["afSleepSafe.csrfTokenName":"peanut"])
		client.get(`/csrfCustomName`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val3")
		
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Form does not contain 'peanut' key")
	}

//	Void testCustomGenFunc() {
//		fail
////		res := fireUp(null, CustomGenFuncMod#).get(`/csrfInvalid`)
////		client.errOn4xx.enabled = false
////		res = Element("form").submitForm
////		
////		verifyEq(res.statusCode, 403)
////		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
//	}
}

internal const class CustomGenFuncMod {
	@Contribute { serviceType=CsrfTokenGeneration# }
	private Void contributeCsrfTokenGeneration(Configuration config) {
//		config["timestamp"] = |Str:Obj? hash| {
//			hash["timestamp"] = DateTime.now(1sec)
//		}
	}	
}
