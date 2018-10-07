using afIoc
using afIocConfig
using afBedSheet
using afConcurrent::ActorPools
using concurrent::ActorPool
using util::JsonInStream

@NoDoc
const class SleepSafeModule {
	
	Void defineServices(RegistryBuilder bob) {
		bob.addService(CsrfCrypto#)
		bob.addService(SleepSafeMiddleware#)
		bob.addService(CsrfTokenGeneration#)
		bob.addService(CsrfTokenValidation#)
	}

	Void onRegistryStartup(Configuration config) {
		scope := config.scope
		config["afSleepSafe.csrfKeyGen"] = |->| {
			crypto := (CsrfCrypto) scope.serviceById(CsrfCrypto#.qname)
			crypto.generateKey
		}
		config["afSleepSafe.logGuards"] = |->| {
			middleware := (SleepSafeMiddleware) scope.serviceById(SleepSafeMiddleware#.qname)
			msg := "SleepSafe knowing your application is protected against: "
			msg += middleware.guards.map { it.protectsAgainst }.unique.sort.join(", ")
			typeof.pod.log.info(msg)
		}
	}

	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		// request checkers
		config[SessionHijackGuard#]	= config.build(SessionHijackGuard#)
		config[CsrfTokenGuard#]		= config.build(CsrfTokenGuard#)
		
		// header setters
		config[CspGuard#]			= config.build(CspGuard#)
		config[ContentTypeGuard#]	= config.build(ContentTypeGuard#)
		config[FrameOptionsGuard#]	= config.build(FrameOptionsGuard#)
		config[ReferrerPolicyGuard#]= config.build(ReferrerPolicyGuard#)
		config[XssProtectionGuard#]	= config.build(XssProtectionGuard#)
	}

	@Contribute { serviceType=CsrfTokenGeneration# }
	Void contributeCsrfTokenGeneration(Configuration config, ConfigSource configSrc, HttpSession httpSession) {
		config["timestamp"] = |Str:Obj? hash| {
			hash["ts"] = Base64.toB64(DateTime.nowTicks / 1ms.ticks)
		}
		config["sessionId"] = |Str:Obj? hash| {
			if (httpSession.exists)
				hash["sId"] = httpSession.id
		}
	}

	@Contribute { serviceType=CsrfTokenValidation# }
	Void contributeCsrfTokenValidation(Configuration config, ConfigSource configSrc, HttpRequest httpRequest, HttpSession httpSession) {
		config["timestamp"] = |Str:Obj? hash| {
			timeout 	:= (Duration)  configSrc.get("afSleepSafe.csrfTokenTimeout", Duration#)
			timestamp	:= Base64.fromB64(hash.get("ts", "0")) * 1ms.ticks
			duration	:= Duration(DateTime.nowTicks - timestamp)
			httpRequest.stash["afSleepSafe.csrf.tokenTs"] = DateTime.makeTicks(timestamp)
			if (duration >= timeout)
				throw Err("Suspected CSRF attack - Token expired. Token exceeds ${timeout} timeout by ${(duration-timeout).toLocale}")
		}
		config["sessionId"] = |Str:Obj? hash| {
			if (hash.containsKey("sId")) {
				if (!httpSession.exists)
					// no session means a stale link
					// we could throw an CSRF err, but more likely the app will want to redirect to a login page 
					return
				if (httpSession.id != hash["sId"])
					throw Err("Suspected CSRF attack - Session ID mismatch")
//					throw Err("Session ID mismatch: $httpSession.id != " + hash["sId"].toStr)
			}
			// if no sId but HTTP session exists...
			// that's normal if the session is created *after* the token is generated
			// don't force the user to re-gen the csrf token - we're supposed to be invisible (almost!)
		}
	}

	@Contribute { serviceType=Routes# }
	Void contributeRoutes(Configuration config, ConfigSource configSrc, HttpRequest httpReq) {
		reportUri := (Uri?             ) configSrc.get("afSleepSafe.csp.report-uri", Uri#, false)
		reportFn  := (|Str:Obj?->Obj?|?) configSrc.get("afSleepSafe.cspReportFn", null, false)
		if (reportUri != null && reportFn != null) {
			routeFn	:=  |->Obj?| {
				jstr := httpReq.body.str ?: "null"
				json := null
				try json = JsonInStream(jstr.in).readJson
				catch (ParseErr perr)
					throw HttpStatus.makeErr(400, "CSP Reporter - Invalid JSON Data", Err(jstr))
				jobj := json as Str:Obj?
				if (jobj == null)
					throw HttpStatus.makeErr(400, "CSP Reporter - Invalid JSON Data", Err(jstr))
				return reportFn(jobj) ?: Text.fromPlain("OK")
			}.toImmutable
			
			config.add(Route(reportUri,	routeFn, "POST"))
		}
	}
	
	@Contribute { serviceType=MiddlewarePipeline# }
	Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
		// given the Session Hijack guard needs to load the session cookie (potentially from a database)
		// lets not protect *every* request, but let static assets slip through
		config.set("afSleepSafe.guards", middleware).after("afBedSheet.assets").before("afBedSheet.routes")
	}

	@Contribute { serviceType=FactoryDefaults# }
	Void contributeFactoryDefaults(Configuration config) {
		scope := config.scope
		
		config["afSleepSafe.rejectedStatusCode"]	= "403"
		
		config["afSleepSafe.csrfTokenName"]			= "_csrfToken"
		config["afSleepSafe.csrfTokenTimeout"]		= "61min"	// ensure user sessions time out before CSRF tokens
		config["afSleepSafe.frameOptions"]			= "SAMEORIGIN"
		config["afSleepSafe.referrerPolicy"]		= "no-referrer, strict-origin-when-cross-origin"
		config["afSleepSafe.sameOriginWhitelist"]	= ""
		config["afSleepSafe.sessionHijackEncrypt"]	= true
		config["afSleepSafe.sessionHijackHeaders"]	= "User-Agent, Accept-Language"
		config["afSleepSafe.xssProtectionEnable"]	= true
		config["afSleepSafe.xssProtectionMode"]		= "block"

		config["afSleepSafe.csp.default-src"]		= "'self'"
		config["afSleepSafe.csp.object-src"]		= "'none'"
		config["afSleepSafe.csp.base-uri"]			= "'self'"
		config["afSleepSafe.csp.form-action"]		= "'self'"
		config["afSleepSafe.csp.frame-ancestors"]	= "'self'"
		config["afSleepSafe.csp.report-uri"]		= "/_sleepSafeCspViolation"
		config["afSleepSafe.cspReportOnly"]			= false
		config["afSleepSafe.cspReportFn"]			= |Str:Obj? report| {
			httpReq := (HttpRequest) scope.serviceById(HttpRequest#.qname)
			txt := JsonWriter(true).writeJson(report)
			typeof.pod.log.warn("Content-Security-Policy Violation:\nUser-Agent: ${httpReq.headers.userAgent}\n${txt}")
		}
	}

	@Contribute { serviceType=ActorPools# }
	Void contributeActorPools(Configuration config) {
		config["csrfKeyGen"] = ActorPool() { it.name = "CSRF Key Gen" }
	}
}
