using afIoc
using afIocConfig::ApplicationDefaults
using afBounce
using afBedSheet
using concurrent::Actor

internal abstract class SleepSafeTest : Test {
	BedServer? 	server
	BedClient? 	client
	
	BedClient fireUp([Str:Str?]? appConfig := null) {
		Actor.locals["test.appConfig"] = appConfig
		server	= BedServer(SleepSafeModule#.pod).addModule(WebTestModule#).startup
		server.inject(this)
		client = server.makeClient
		
		return client
	}
	
	override Void teardown() {
		server?.shutdown
	}
}

internal const class WebTestModule {
	
	@Contribute { serviceType=Routes# }
	Void contributeRoutes(Configuration config) {
		config.add(Route(`/okay`, Text.fromPlain("Okay")))
	}

	@Contribute { serviceType=ApplicationDefaults# }
	Void contributeApplicationDefaults(Configuration config) {
		appConfig := ([Str:Str?]?) Actor.locals["test.appConfig"]
		appConfig?.each |v, k| { config[k] = v }
	}

//	@Override
//	IocEnv overrideIocEnv() {
//        IocEnv.fromStr("Testing")
//    }
}
