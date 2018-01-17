
internal class TestReferrerPolicyGuard : SleepSafeTest {
	
	Void testDefaultConfig() {
		res := fireUp.get(`/getPlain`)
		verifyEq(res.headers.referrerPolicy, "no-referrer, strict-origin-when-cross-origin")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testNullConfig() {
		res := fireUp([,], ["afSleepSafe.referrerPolicy":null]).get(`/getPlain`)
		verifyFalse(res.headers.val.containsKey("Referrer-Policy"))
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testOtherConfig() {
		res := fireUp([,], ["afSleepSafe.referrerPolicy":"same-origin"]).get(`/getPlain`)
		verifyEq(res.headers.referrerPolicy, "same-origin")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
