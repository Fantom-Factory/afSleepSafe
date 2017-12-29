using afBounce
using afIoc::Contribute
using afIoc::Configuration
using afBedSheet
using concurrent::Actor
using concurrent::AtomicRef

internal class TestCsrfProtection : SleepSafeTest {
	
	Void testCsrfHappy() {
		fireUp([CsrfTestModule#])
		client.get(`/csrfHappy`)
		FormInput("[name=nom]").verifyValueEq("val1")
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
	}

	Void testCsrfNoFormData() {
		fireUp([CsrfTestModule#])
		client.get(`/csrfNoForm`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - No form data")
	}

	Void testCsrfNotFound() {
		fireUp([CsrfTestModule#])
		client.get(`/csrfNotFound`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Form does not contain '_csrfToken' key")
	}

	Void testCsrfInvalid() {
		fireUp([CsrfTestModule#])
		client.get(`/csrfInvalid`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}

	Void testCsrfTokenTimeout() {
		fireUp([CsrfTestModule#], ["afSleepSafe.csrfTokenTimeout":"20ms"])
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		Actor.sleep(30ms)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str[0..<-6], "403 - Suspected CSRF attack - Token exceeds 20ms timeout")
	}

	Void testCsrfCustomTokenName() {
		fireUp([CsrfTestModule#], ["afSleepSafe.csrfTokenName":"peanut"])
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
		fireUp([CsrfTestModule#, CsrfCustomGenFuncMod1#])
		client.get(`/csrfHappy`)
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")
		verifyEq(CsrfCustomGenFuncMod1.customValRef.val, "Princess Daisy")
	}

	Void testCsrfCustomFuncs2() {
		fireUp([CsrfTestModule#, CsrfCustomGenFuncMod2#])
		client.get(`/csrfHappy`)
		client.errOn4xx.enabled = false
		res := Element("form").submitForm
		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Custom Boom!")
	}

	Void testCsrfPlainTextEnc() {
		fireUp([CsrfTestModule#])
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
		fireUp([CsrfTestModule#])
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
		fireUp([CsrfTestModule#])
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
		fireUp([CsrfTestModule#])
		client.get(`/setSession`)
		client.get(`/csrfHappy`)
		res := Element("form").submitForm
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=val1")

		client.get(`/csrfBadSession`)
		client.errOn4xx.enabled = false
		res = Element("form").submitForm
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Invalid '_csrfToken' value")
	}
	
	// session id texts
}

internal const class CsrfTestModule {

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
			tokenFn := (|->Str|) req.stash["afSleepSafe.csrfTokenFn"]
			req.stash["afSleepSafe.csrfToken"] = tokenFn()
			return Text.fromPlain("Okay")
		}.toImmutable

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
