using afIoc
using afIocConfig
using afBedSheet
using afConcurrent::ActorPools
using concurrent::ActorPool

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
		config["csrfKeyGen"] = |->| {
			crypto := (CsrfCrypto) scope.serviceById(CsrfCrypto#.qname)
			crypto.generateKey
		}
	}

	@Contribute { serviceType=SleepSafeMiddleware# }
	Void contributeSleepSafeMiddleware(Configuration config) {
		config["xFrameOptions"]		= config.build(XFrameOptionsGuard#)
		config["csrf"]				= config.build(CsrfGuard#)
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
	Void contributeCsrfTokenValidation(Configuration config, ConfigSource configSrc, HttpSession httpSession) {
		config["timestamp"] = |Str:Obj? hash| {
			timeout 	:= (Duration)  configSrc.get("afSleepSafe.csrfTokenTimeout", Duration#)
			timestamp	:= Base64.fromB64(hash.get("ts", "0")) * 1ms.ticks
			duration	:= Duration(DateTime.nowTicks - timestamp)
			if (duration >= timeout)
				throw Err("Token exceeds ${timeout} timeout: ${duration}")
		}
		config["sessionId"] = |Str:Obj? hash| {
			if (hash.containsKey("sId")) {
				if (!httpSession.exists)
					// no session means a stale link
					// we could throw an CSRF err, but more likely the app will want to redirect to a login page 
					return
				if (httpSession.id != hash["sId"])
					throw Err("Session ID mismatch")
			}
			// if no sId but HTTP session exists...
			// that's normal 'cos the session is normally created *after* the token is generated
			// don't force the user to re-gen the csrf token - we're supposed to be invisible (almost!)
		}
	}

	@Contribute { serviceType=MiddlewarePipeline# }
	Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
		config.set("SleepSafeMiddleware", middleware).before("afBedSheet.routes")
	}

	@Contribute { serviceType=FactoryDefaults# }
	private Void contributeFactoryDefaults(Configuration config) {
		config["afSleepSafe.deniedStatusCode"]		= "403"
		config["afSleepSafe.xFrameOptions"]			= "sameorigin"
		config["afSleepSafe.csrfTokenName"]			= "_csrfToken"
		config["afSleepSafe.csrfTokenTimeout"]		= "200ms"
	}

	@Contribute { serviceType=ActorPools# }
	private Void contributeActorPools(Configuration config) {
		config["csrfKeyGen"] = ActorPool() { it.name = "CSRF Key Gen" }
	}
}
