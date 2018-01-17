
internal class TestFrameOptionsGuard : SleepSafeTest {
	
	Void testDefaultConfig() {
		res := fireUp.get(`/getHtml`)
		verifyEq(res.headers.xFrameOptions, "SAMEORIGIN")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testNullConfig() {
		res := fireUp([,], ["afSleepSafe.frameOptions":null]).get(`/getHtml`)
		verifyFalse(res.headers.val.containsKey("X-Frame-Options"))
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testOtherConfig() {
		res := fireUp([,], ["afSleepSafe.frameOptions":"DENY"]).get(`/getHtml`)
		verifyEq(res.headers.xFrameOptions, "DENY")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testIsHtmlOnly() {
		res := fireUp.get(`/getPlain`)
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
		verifyFalse(res.headers.val.containsKey("X-Frame-Options"))
	}
}
