
internal class TestXXssProtectionGuard : SleepSafeTest {

	Void testDefaultConfig() {
		res := fireUp.get(`/get`)
		verifyEq(res.headers.xXssProtection, "1; mode=block")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testDisableConfig() {
		res := fireUp([,], ["afSleepSafe.xXssProtectionEnable":false]).get(`/get`)
		verifyEq(res.headers.xXssProtection, "0")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testModeConfig() {
		res := fireUp([,], ["afSleepSafe.xXssProtectionMode":null]).get(`/get`)
		verifyEq(res.headers.xXssProtection, "1")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
