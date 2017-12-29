using afBounce
using afIoc::Contribute
using afIoc::Configuration
using afBedSheet
using concurrent::Actor
using concurrent::AtomicRef

internal class TestCsrfTokenGuard : SleepSafeTest {
	
	Void testCsrfHappy() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfHappy`)
		FormInput("[name=nom]").verifyValueEq("val1")
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
	}

	Void testCsrfNoFormData() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfNoForm`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - No form data")
	}

	Void testCsrfNotFound() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfNotFound`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Form does not contain '_csrfToken' key")
	}

	Void testCsrfInvalid() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfInvalid`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	Void testCsrfTokenTimeout() {
		fireUp([CsrfTokenTestModule#], ["afSleepSafe.csrfTokenTimeout":"20ms"])
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		Actor.sleep(30ms)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str[0..<-6], "403 - Suspected CSRF attack - Token exceeds 20ms timeout")
	}

	Void testCsrfCustomTokenName() {
		fireUp([CsrfTokenTestModule#], ["afSleepSafe.csrfTokenName":"peanut"])
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
		fireUp([CsrfTokenTestModule#, CsrfCustomGenFuncMod1#])
		client.get(`/csrfHappy`)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
		verifyEq(CsrfCustomGenFuncMod1.customValRef.val, "Princess Daisy")
	}

	Void testCsrfCustomFuncs2() {
		fireUp([CsrfTokenTestModule#, CsrfCustomGenFuncMod2#])
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Custom Boom!")
	}

	Void testCsrfPlainTextEnc() {
		fireUp([CsrfTokenTestModule#])
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

	Void testCsrfMultipartEnc() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfMultipartHappy`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val6")

		client.get(`/csrfMultipartUnhappy`)
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	Void testCsrfQueryUri() {
		fireUp([CsrfTokenTestModule#])
		client.get(`/csrfUriHappy`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val6")

		client.get(`/csrfUriUnhappy`)
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	Void testCsrfSessionIdCheck() {
		fireUp([CsrfTokenTestModule#, CsrfCustomSessFuncMod#])
		client.get(`/csrfSetSession`)
		client.get(`/csrfHappy`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")

		client.get(`/csrfBadSession`)	// like /csrfhappy, only it changes the sessId in the token
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Session ID mismatch")
	}
}

internal const class CsrfTokenTestModule {

	@Contribute { serviceType=Routes# }
	Void contributeRoutes(Configuration config) {
		scope := config.scope
		req   := (HttpRequest) scope.serviceByType(HttpRequest#)
		ses	  := (HttpSession) scope.serviceByType(HttpSession#)

		csrfHtml := "<!DOCTYPE html><html><body><form method='post' enctype='application/x-www-form-urlencoded' action='/post'><input name='nom' value='val1'><input type='hidden' name='_csrfToken' value='%{csrfToken}'></form></body></html>"

		csrfHappy := |->Text| {
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok)
			return Text.fromHtml(str)
		}.toImmutable

		csrfCustomName := |->Text| {
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("_csrfToken", "peanut").replace("val1", "val3")
			return Text.fromHtml(str)
		}.toImmutable

		csrfPlainTextHappy := |->Text| {
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("val1", "val5").replace("application/x-www-form-urlencoded", "text/plain")
			return Text.fromHtml(str)
		}.toImmutable

		csrfPlainTextUnhappy := |->Text| {
			str := csrfHtml.replace("%{csrfToken}", "XXXXXX").replace("application/x-www-form-urlencoded", "text/plain")
			return Text.fromHtml(str)
		}.toImmutable

		csrfMultipartHappy := |->Text| {
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("val1", "val6").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		csrfMultipartUnhappy := |->Text| {
			str := csrfHtml.replace("%{csrfToken}", "XXXXXX").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		csrfUriHappy := |->Text| {
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("_csrfToken", "meh").replace("/post", "/post?_csrfToken=$tok").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2").replace("val1", "val6")
			return Text.fromHtml(str) 
		}.toImmutable

		csrfUriUnhappy := |->Text| {
			str := csrfHtml.replace("_csrfToken", "meh").replace("/post", "/post?_csrfToken=XXXXXXXX").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		csrfSetSessionFn := |->Text| {
			ses.id
			req.stash["afSleepSafe.csrfToken"] = ((|->Str|) req.stash["afSleepSafe.csrfTokenFn"])()
			return Text.fromPlain("Okay")
		}.toImmutable
		
		csrfBadSessionFn := |->Text| {
			req.stash["newSessionId"] = true
			req.stash["afSleepSafe.csrfToken"] = ((|->Str|) req.stash["afSleepSafe.csrfTokenFn"])()
			return csrfHappy()			
		}

		config.add(Route(`/csrfHappy`, 				csrfHappy))
		config.add(Route(`/csrfNoForm`,				Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'></form></body></html>")))
		config.add(Route(`/csrfNotFound`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='nom' value='val'></form></body></html>")))
		config.add(Route(`/csrfInvalid`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='_csrfToken' value='XXXXXXXX'></form></body></html>")))
		config.add(Route(`/csrfCustomEnc`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post' enctype='slimer/dude'><input type='hidden' name='_csrfToken' value='XXXXXXXX'><input type='hidden' name='nom' value='val4'></form></body></html>")))
		config.add(Route(`/csrfCustomName`,			csrfCustomName))
		config.add(Route(`/csrfPlainHappy`,			csrfPlainTextHappy))
		config.add(Route(`/csrfPlainUnhappy`,		csrfPlainTextUnhappy))
		config.add(Route(`/csrfMultipartHappy`,		csrfMultipartHappy))
		config.add(Route(`/csrfMultipartUnhappy`,	csrfMultipartUnhappy))
		config.add(Route(`/csrfUriHappy`,			csrfUriHappy))
		config.add(Route(`/csrfUriUnhappy`,			csrfUriUnhappy))
		config.add(Route(`/csrfSetSession`,			csrfSetSessionFn))
		config.add(Route(`/csrfBadSession`,			csrfBadSessionFn))
	}
}

internal const class CsrfCustomGenFuncMod1 {
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

internal const class CsrfCustomGenFuncMod2 {
	@Contribute { serviceType=CsrfTokenValidation# }
	private Void contributeCsrfTokenValidation(Configuration config) {
		config["custom"] = |Str:Obj? hash| {
			throw Err("Custom Boom!")
		}
	}
}

internal const class CsrfCustomSessFuncMod {
	@Contribute { serviceType=CsrfTokenGeneration# }
	private Void contributeCsrfTokenGeneration(Configuration config) {
		scope := config.scope
		config.set("custom", |Str:Obj? hash| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			if (req.stash["newSessionId"] == true)
				hash["sId"] = 13
		}).after("sessionId")
	}
}
