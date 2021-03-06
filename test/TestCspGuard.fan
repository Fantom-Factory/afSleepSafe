using afConcurrent::AtomicList

internal class TestCspGuard : SleepSafeTest {

	Void testDefaultHeaders() {
		res := fireUp.get(`/getHtml`)
		verifyEq(res.headers["Content-Security-Policy"], "base-uri 'self'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; object-src 'none'; report-uri /_sleepSafeCspViolation")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")
	}

	Void testDefaultReporting() {
		fireUp.get(`/getHtml`)	// warm up

		logs		:= AtomicList()
		handlerRef	:= Unsafe(|LogRec rec| { logs.add(rec) })
		Log.addHandler(handlerRef.val)
		try {
			client.postJsonObj(`/_sleepSafeCspViolation`, ["big":"balloons"])
		} finally {
			Log.removeHandler(handlerRef.val)
		}
		
		verifyEq(logs.size, 1)

		log := (LogRec) logs.first
		verifyEq(log.level, LogLevel.warn)
		verifyEq(log.msg, "Content-Security-Policy Violation:\nUser-Agent: null\n{\"big\": \"balloons\"}")
	}
	
	Void testCustomDirectives() {
		res := fireUp([,], [
			"afSleepSafe.csp.base-uri"			: null,
			"afSleepSafe.csp.form-action"		: null,
			"afSleepSafe.csp.frame-ancestors"	: null,
			"afSleepSafe.csp.default-src"		: null,
			"afSleepSafe.csp.object-src"		: null,
			"afSleepSafe.csp.big"				: "balloons",
		]).get(`/getHtml`)
		verifyEq(res.headers["Content-Security-Policy"], "big balloons; report-uri /_sleepSafeCspViolation")
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")		
	}

	Void testDisableReporting1() {
		fireUp([,], [
			"afSleepSafe.csp.report-uri"	: null,
		]).get(`/getHtml`)

		logs		:= AtomicList()
		handlerRef	:= Unsafe(|LogRec rec| { logs.add(rec) })
		Log.addHandler(handlerRef.val)
		try {
			client.errOn4xx.enabled = false
			res := client.postJsonObj(`/_sleepSafeCspViolation`, ["big":"balloons"])
			verifyEq(404, res.statusCode)
		} finally {
			Log.removeHandler(handlerRef.val)
		}
		
		verifyEq(logs.size, 0)
	}

	Void testDisableReporting2() {
		fireUp([,], [
			"afSleepSafe.cspReportFn"	: null,
		]).get(`/getHtml`)

		logs		:= AtomicList()
		handlerRef	:= Unsafe(|LogRec rec| { logs.add(rec) })
		Log.addHandler(handlerRef.val)
		try {
			client.errOn4xx.enabled = false
			res := client.postJsonObj(`/_sleepSafeCspViolation`, ["big":"balloons"])
			verifyEq(404, res.statusCode)
		} finally {
			Log.removeHandler(handlerRef.val)
		}
		
		verifyEq(logs.size, 0)
	}

	Void testCustomReporting() {
		logs		:= AtomicList()
		fireUp([,], [
			"afSleepSafe.cspReportFn"	: |Str:Obj? report| { logs.add(report.toStr) }.toImmutable,
		])

		res := client.postJsonObj(`/_sleepSafeCspViolation`, ["big":"balloons"])
		
		verifyEq(logs.size, 1)
		verifyEq(logs.first, "[big:balloons]")
	}

	Void testReportOnly() {
		logs		:= AtomicList()
		res := fireUp([,], [
			"afSleepSafe.cspReportOnly"	: true,
		]).get(`/getHtml`)

		verifyNull(res.headers.contentSecurityPolicy)
		verifyNotNull(res.headers.contentSecurityPolicyReportOnly)
	}

	Void testCspIsForHtmlOnly() {
		res := fireUp.get(`/getPlain`)
		verifyEq(res.statusCode, 200)
		verifyEq(res.body.str, "Okay")

		verifyNull(res.headers.contentSecurityPolicy)
		verifyNull(res.headers.contentSecurityPolicyReportOnly)
	}
}
