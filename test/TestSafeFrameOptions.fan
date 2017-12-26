
internal class TestSafeFrameOptions : SleepSafeTest {
	
	Void testDefaultConfig() {
		res := fireUp.get(`/okay`)
		verifyEq(res.headers.xFrameOptions, "sameorigin")
	}

	Void testNullConfig() {
		res := fireUp(["afSleepSafe.frameOptions":null]).get(`/okay`)
		verifyFalse(res.headers.val.containsKey("X-Frame-Options"))
	}

	Void testOtherConfig() {
		res := fireUp(["afSleepSafe.frameOptions":"deny"]).get(`/okay`)
		verifyEq(res.headers.xFrameOptions, "deny")
	}
}
