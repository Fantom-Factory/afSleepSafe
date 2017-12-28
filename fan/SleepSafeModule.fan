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
		config["xFrameOptions"]		= config.build(XFrameOptionsProtection#)
		config["csrf"]				= config.build(CsrfProtection#)
	}

	@Contribute { serviceType=CsrfTokenGeneration# }
	Void contributeCsrfTokenGeneration(Configuration config, ConfigSource configSrc, HttpSession httpSession) {
		config["timestamp"] = |Str:Obj? hash| {
			timeoutResolution := (Duration?) configSrc.get("afSleepSafe.csrfTimeoutResolution", Duration#)
			hash["timestamp"] = DateTime.now(timeoutResolution)
		}
		config["sessionId"] = |Str:Obj? hash| {
			if (httpSession.exists)
				hash["sessionId"] = httpSession.id
		}
	}

	@Contribute { serviceType=CsrfTokenValidation# }
	Void contributeCsrfTokenValidation(Configuration config, ConfigSource configSrc) {
		config["timestamp"] = |Str:Obj? hash| {
			timeout 			:= (Duration)  configSrc.get("afSleepSafe.csrfTokenTimeout", Duration#)
			timeoutResolution	:= (Duration?) configSrc.get("afSleepSafe.csrfTimeoutResolution", Duration#)
			duration := DateTime.now(timeoutResolution) - ((DateTime) hash["timestamp"])
			if (duration >= timeout)
				throw Err("Token exceeds ${timeout} timeout: ${duration}")
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
		config["afSleepSafe.csrfTokenTimeout"]		= "2ms"
		config["afSleepSafe.csrfTimeoutResolution"]	= "1sec"
	}

	@Contribute { serviceType=ActorPools# }
	private Void contributeActorPools(Configuration config) {
		config["csrfKeyGen"] = ActorPool() { it.name = "CSRF Key Gen" }
	}
}
