
internal class TestXFrameOptionsGuard : SleepSafeTest {
	
	Void testDefaultConfig() {
		res := fireUp.get(`/get`)
		verifyEq(res.headers.xFrameOptions, "sameorigin")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testNullConfig() {
		res := fireUp([,], ["afSleepSafe.xFrameOptions":null]).get(`/get`)
		verifyFalse(res.headers.val.containsKey("X-Frame-Options"))
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testOtherConfig() {
		res := fireUp([,], ["afSleepSafe.xFrameOptions":"deny"]).get(`/get`)
		verifyEq(res.headers.xFrameOptions, "deny")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
