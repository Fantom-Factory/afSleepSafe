using afIoc::Contribute
using afIoc::Configuration
using afBedSheet
using afButter::ButterRequest
using afButter::QualityValues

internal class TestSessionHijackGuard : SleepSafeTest {
	
	Void testDefaultHappyCase() {
		fireUp([SessionHijackTestModule#])

		res := client.sendRequest(ButterRequest(`/setSession`) {
			it.headers.userAgent = "afButter"
			it.headers.acceptLanguage = QualityValues("da")
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
		verifyNotNull(client.webSession)

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/get`) {
			it.headers.userAgent = "afRuby"
			it.headers.acceptLanguage = QualityValues("niet")
		})		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected Cookie Hijacking - Session parameters have changed: vy3wLnzk9U2-DhRA0zU24v1xXtY != oEAIyzglHzzYqfxI55KMB5LwMm4")
		verifyNull(client.webSession)
	}
	
	Void testUserAgentOnly() {
		fireUp([SessionHijackTestModule#])

		res := client.sendRequest(ButterRequest(`/setSession`) {
			it.headers.userAgent = "afButter"
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
		verifyNotNull(client.webSession)

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/hasSession`) {
			it.headers.userAgent = "afRuby"
		})		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected Cookie Hijacking - Session parameters have changed: rChkbCpDglo589QmjSLykTBTkro != qYesI6InFwCXqfUUzXEuhbPM8pU")
		verifyNull(client.webSession)
	}
	
	Void testAcceptLangOnly() {
		fireUp([SessionHijackTestModule#])

		res := client.sendRequest(ButterRequest(`/setSession`) {
			it.headers.acceptLanguage = QualityValues("en")
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
		verifyNotNull(client.webSession)

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/get`) {
			it.headers.acceptLanguage = QualityValues("ru")
		})		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected Cookie Hijacking - Session parameters have changed: 9ytri1rPOG30PmsVzQ0TWXZm814 != CeRo8UO6WsoJ_PRZp3cxEeG_7-E")
		verifyNull(client.webSession)
	}

	Void testEncrypt() {
		fireUp([SessionHijackTestModule#], ["afSleepSafe.sessionHijackEncrypt":false])

		res := client.sendRequest(ButterRequest(`/setSession`) {
			it.headers.userAgent = "007"
			it.headers.acceptLanguage = QualityValues("en")
		})		

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/get`) {
			it.headers.userAgent = "rominov"
			it.headers.acceptLanguage = QualityValues("ru")
		})		
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected Cookie Hijacking - Session parameters have changed: User-Agent: 007, Accept-Language: en != User-Agent: rominov, Accept-Language: ru")
	}

	Void testCustomHeaders() {
		fireUp([SessionHijackTestModule#], ["afSleepSafe.sessionHijackEncrypt":false, "afSleepSafe.sessionHijackHeaders":"wot, ever"])

		res := client.sendRequest(ButterRequest(`/setSession`) {
			it.headers["wot"]  = "foo"
			it.headers["ever"] = "bar"
		})

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/get`))
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected Cookie Hijacking - Session parameters have changed: wot: foo, ever: bar != wot: , ever: ")
	}
}


internal const class SessionHijackTestModule {

	@Contribute { serviceType=Routes# }
	Void contributeRoutes(Configuration config) {
		scope := config.scope
		req   := (HttpRequest) scope.serviceByType(HttpRequest#)
		ses	  := (HttpSession) scope.serviceByType(HttpSession#)

		setSessionFn := |->Text| {
			ses["wot"] = "ever"	// need to stick something in the session for Bounce to think it exists
			return Text.fromPlain("Okay")
		}.toImmutable
		
		hasSessionFn := |->Text| {
			ses["wot"] = "ever"	// need to stick something in the session for Bounce to think it exists
			return Text.fromPlain("Okay")
		}.toImmutable
		
		config.add(Route(`/setSession`,			setSessionFn))
		config.add(Route(`/hasSession`,			setSessionFn))
	}
	
	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config.remove(CsrfTokenGuard#)
		config.remove(SameOriginGuard#)
	}
}