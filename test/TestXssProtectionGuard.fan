
internal class TestXssProtectionGuard : SleepSafeTest {

	Void testDefaultConfig() {
		res := fireUp.get(`/getHtml`)
		verifyEq(res.headers.xXssProtection, "1; mode=block")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testDisableConfig() {
		res := fireUp([,], ["afSleepSafe.xssProtectionEnable":false]).get(`/getHtml`)
		verifyEq(res.headers.xXssProtection, "0")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testModeConfig() {
		res := fireUp([,], ["afSleepSafe.xssProtectionMode":null]).get(`/getHtml`)
		verifyEq(res.headers.xXssProtection, "1")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
	
	Void testIsHtmlOnly() {
		res := fireUp.get(`/getPlain`)
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
		verifyFalse(res.headers.val.containsKey("X-XSS-Protection"))
	}
}
