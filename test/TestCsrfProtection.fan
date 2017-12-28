using afBounce
using afIoc::Contribute
using afIoc::Configuration
using concurrent::Actor
using concurrent::AtomicRef

internal class TestCsrfProtection : SleepSafeTest {
	
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

	Void testCsrfCustomFuncs1() {
		fireUp(null, CustomGenFuncMod1#)
		client.get(`/csrfHappy`)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
		verifyEq(CustomGenFuncMod1.customValRef.val, "Princess Daisy")
	}

	Void testCsrfCustomFuncs2() {
		fireUp(null, CustomGenFuncMod2#)
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Custom Boom!")
	}

	Void testCsrfPlainTextEnc() {
		fireUp()
		client.get(`/csrfPlainHappy`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val5")

		client.get(`/csrfPlainUnhappy`)
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	// test plain-text
	// test multipart
	// test multipart uri query
}

internal const class CustomGenFuncMod1 {
	static const AtomicRef customValRef	:= AtomicRef(null)

	@Contribute { serviceType=CsrfTokenGeneration# }
	private Void contributeCsrfTokenGeneration(Configuration config) {
		config["custom"] = |Str:Obj? hash| {
			hash["custom"] = "Princess Daisy"
		}
	}	

	@Contribute { serviceType=CsrfTokenValidation# }
	private Void contributeCsrfTokenValidation(Configuration config) {
		config["custom"] = |Str:Obj? hash| {
			customValRef.val = hash["custom"]
		}
	}
}

internal const class CustomGenFuncMod2 {
	@Contribute { serviceType=CsrfTokenValidation# }
	private Void contributeCsrfTokenValidation(Configuration config) {
		config["custom"] = |Str:Obj? hash| {
			throw Err("Custom Boom!")
		}
	}
}
