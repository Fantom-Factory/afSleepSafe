
internal class TestContentTypeGuard : SleepSafeTest {

	Void testDefaultConfig() {
		res := fireUp.get(`/getPlain`)
		verifyEq(res.headers.xContentTypeOptions, "nosniff")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
