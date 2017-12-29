using afIoc::Contribute
using afIoc::Configuration
using afButter::ButterRequest
using afBounce::Element
using afBounce::FormInput

internal class TestCsrfSameOriginGuard : SleepSafeTest {

	Void testSameOriginHappy() {
		fireUp([ReferrerGuardTestMod#])
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.referrer = `http://localhost/wotever.html`
			it.body.form = ["nom":"valX"]
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=valX")

		res = client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://localhost/wotever.html`
			it.body.form = ["nom":"valY"]
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=valY")
	}

	Void testDiffReferrer() {
		fireUp([ReferrerGuardTestMod#])
		client.errOn4xx.enabled = false
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.referrer = `http://example.com`
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Referrer does not match Host: http://example.com/ != http://localhost/")
	}

	Void testDiffOrigin() {
		fireUp([ReferrerGuardTestMod#])
		client.errOn4xx.enabled = false
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://example.com`
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Origin does not match Host: http://example.com/ != http://localhost/")
	}

	Void testNoOriginNoRefferer() {
		fireUp([ReferrerGuardTestMod#])
		client.errOn4xx.enabled = false
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - HTTP request contains neither a Referrer nor an Origin header")
	}
}

internal const class ReferrerGuardTestMod {
	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config.remove("csrfToken")
	}
}
