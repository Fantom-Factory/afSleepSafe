using afIoc
using afIocConfig
using afBedSheet
using afConcurrent::ActorPools
using concurrent::ActorPool

@NoDoc
const class SleepSafeModule {
	
	Void defineServices(RegistryBuilder bob) {
		bob.addService(CsrfCrypto#)
		bob.addService(CsrfTokenGeneration#)
		bob.addService(CsrfTokenValidation#)
	}

	@Build
	private SleepSafeMiddleware buildSleepSafeMiddleware(Scope scope, ConfigSource configSrc) {
		protection := Protection[,]
		
		frameOptions := configSrc["afSleepSafe.frameOptions"]?.toStr
		if (frameOptions != null)
			protection.add(SafeFrameOptions(frameOptions))

		// FIXME disable csrf?
		protection.add(scope.build(SafeCsrf#))
		
		return scope.build(SleepSafeMiddleware#, [protection])
	}

	private Void onRegistryStartup(Configuration config) {
		scope := config.scope
		config["csrfKeyGen"] = |->| {
			crypto := (CsrfCrypto) scope.serviceById(CsrfCrypto#.qname)
			crypto.generateKey
		}
	}

	@Contribute { serviceType=CsrfTokenGeneration# }
	private Void contributeCsrfTokenGeneration(Configuration config, HttpSession httpSession) {
//		scope := config.scope
		config["timestamp"] = |Str:Obj? hash| {
			hash["timestamp"] = DateTime.now(1sec)
		}
		config["sessionId"] = |Str:Obj? hash| {
			if (httpSession.exists)
				hash["sessionId"] = httpSession.id
		}
	}

	@Contribute { serviceType=CsrfTokenValidation# }
	private Void contributeCsrfTokenValidation(Configuration config) {
		
	}

	@Contribute { serviceType=MiddlewarePipeline# }
	private Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
		config.set("SleepSafeMiddleware", middleware).before("afBedSheet.routes")
	}

	@Contribute { serviceType=FactoryDefaults# }
	private Void contributeFactoryDefaults(Configuration config) {
		config["afSleepSafe.deniedStatusCode"]	= "403"
		config["afSleepSafe.frameOptions"]		= "sameorigin"
		config["afSleepSafe.csrfTokenName"]		= "_csrfBuster"
	}

	@Contribute { serviceType=ActorPools# }
	private Void contributeActorPools(Configuration config) {
		config["csrfKeyGen"] = ActorPool() { it.name = "CSRF Key Gen" }
	}
}
