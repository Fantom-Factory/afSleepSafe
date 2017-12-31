
internal class TestContentTypeGuard : SleepSafeTest {

	Void testDefaultConfig() {
		res := fireUp.get(`/get`)
		verifyEq(res.headers.xContentTypeOptions, "nosniff")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
