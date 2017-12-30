
internal class TestXContentTypeGuard : SleepSafeTest {

	Void testDefaultConfig() {
		res := fireUp.get(`/get`)
		verifyEq(res.headers["X-Content-Type-Options"], "nosniff")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}
