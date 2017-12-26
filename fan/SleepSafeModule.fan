using afIoc
using afIocConfig
using afBedSheet

@NoDoc
const class SleepSafeModule {
	
	Void defineServices(RegistryBuilder bob) {
		
	}

	@Build
	private SleepSafeMiddleware buildSleepSafeMiddleware(Scope scope, ConfigSource configSrc) {
		protection := Protection[,]
		
		frameOptions := configSrc["afSleepSafe.frameOptions"]?.toStr
		if (frameOptions != null)
			protection.add(SafeFrameOptions(frameOptions))
		
		return scope.build(SleepSafeMiddleware#, [protection])
	}

	@Contribute { serviceType=MiddlewarePipeline# }
	private Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
		config.set("SleepSafeMiddleware", middleware).before("afBedSheet.routes")
	}

	@Contribute { serviceType=FactoryDefaults# }
	Void contributeFactoryDefaults(Configuration config) {
		config["afSleepSafe.frameOptions"]	= "sameorigin"
	}
}
