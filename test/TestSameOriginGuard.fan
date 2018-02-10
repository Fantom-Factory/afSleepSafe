using afIoc::Contribute
using afIoc::Configuration
using afIocConfig::ApplicationDefaults
using afButter::ButterRequest
using afBounce::Element
using afBounce::FormInput

internal class TestSameOriginGuard : SleepSafeTest {

	Void testSameOriginHappy() {
		fireUp([NoCsrfTokenMod#])
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
		fireUp([NoCsrfTokenMod#])
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
		fireUp([NoCsrfTokenMod#])
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
		fireUp([NoCsrfTokenMod#])
		client.errOn4xx.enabled = false
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - HTTP request contains neither a Referrer nor an Origin header")
	}

	Void testAltBedSheetHost() {
		fireUp([NoCsrfTokenMod#], ["afBedSheet.host":"http://alt.example.com"])
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://alt.example.com/`
			it.body.form = ["nom":"valX"]
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=valX")

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://localhost`
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Origin does not match Host: http://localhost/ != http://alt.example.com/")
	}

	Void testOriginWhitelist() {
		fireUp([NoCsrfTokenMod#, OriginWhitelistTestMod#])
		res := client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://domain.com`
			it.body.form = ["nom":"valX"]
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=valX")

		res = client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `//noscheme.org`
			it.body.form = ["nom":"valY"]
		})		
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Post, nom=valY")

		client.errOn4xx.enabled = false
		res = client.sendRequest(ButterRequest(`/post`) {
			it.method = "POST"
			it.headers.origin = `http://nogo.com`
			it.body.form = ["nom":"valX"]
		})
		verifyEq(res.statusCode, 403)
		verifyEq(res.body.str, "403 - Suspected CSRF attack - Origin does not match Host: http://nogo.com/ != http://localhost/, http://domain.com/, //noscheme.org/")
	}
}

internal const class NoCsrfTokenMod {
	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config.remove(CsrfTokenGuard#)
		config[SameOriginGuard#] = config.build(SameOriginGuard#)
	}
}

internal const class OriginWhitelistTestMod {
	@Contribute { serviceType=ApplicationDefaults# }
	Void contributeApplicationDefaults(Configuration config) {
		config["afSleepSafe.sameOriginWhitelist"] = `http://domain.com, //noscheme.org/`
	}
}
