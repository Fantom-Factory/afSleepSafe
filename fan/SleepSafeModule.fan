using afIoc
using afIocConfig
using afBedSheet
using afConcurrent::ActorPools
using concurrent::ActorPool

@NoDoc
const class SleepSafeModule {
	
	Void defineServices(RegistryBuilder bob) {
		bob.addService(CsrfCrypto#)
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
	
	@Contribute { serviceType=MiddlewarePipeline# }
	private Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
		config.set("SleepSafeMiddleware", middleware).before("afBedSheet.routes")
	}

	@Contribute { serviceType=FactoryDefaults# }
	Void contributeFactoryDefaults(Configuration config) {
		config["afSleepSafe.frameOptions"]	= "sameorigin"
	}
	
	@Contribute { serviceType=ActorPools# }
	Void contributeActorPools(Configuration config) {
		config["csrfKeyGen"] = ActorPool() { it.name = "CSRF Key Gen" }
	}
}
