
internal class TestFrameOptionsGuard : SleepSafeTest {
	
	Void testDefaultConfig() {
		res := fireUp.get(`/get`)
		verifyEq(res.headers.xFrameOptions, "SAMEORIGIN")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testNullConfig() {
		res := fireUp([,], ["afSleepSafe.frameOptions":null]).get(`/get`)
		verifyFalse(res.headers.val.containsKey("X-Frame-Options"))
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testOtherConfig() {
		res := fireUp([,], ["afSleepSafe.frameOptions":"DENY"]).get(`/get`)
		verifyEq(res.headers.xFrameOptions, "DENY")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
