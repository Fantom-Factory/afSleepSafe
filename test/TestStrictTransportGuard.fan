using afIoc::Contribute
using afIoc::Configuration

internal class TestStrictTransportGuard : SleepSafeTest {
	
	Void testDefaultConfig() {
		fireUp
		res := client.get(`/get`)
		verifyFalse(res.headers.val.containsKey("Strict-Transport-Security"))
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testHstsBasic() {
		fireUp([StrictTransportMod1#])
		res := client.get(`/get`)
		verifyEq(res.headers["Strict-Transport-Security"], "max-age=86400")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testHstsAll() {
		fireUp([StrictTransportMod2#])
		res := client.get(`/get`)
		verifyEq(res.headers["Strict-Transport-Security"], "max-age=63072000; includeSubDomains; preload")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}
}

internal const class StrictTransportMod1 {
	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config[StrictTransportGuard#] = StrictTransportGuard(1day)
	}
}

internal const class StrictTransportMod2 {
	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config[StrictTransportGuard#] = StrictTransportGuard(365day * 2, true, true)
	}
}