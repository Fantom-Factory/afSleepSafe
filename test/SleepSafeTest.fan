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
		server = BedServer(SleepSafeModule#.pod).addModule(WebTestModule#).startup
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
		scope := config.scope

		csrfHtml := "<!DOCTYPE html><html><body><form method='post' action='/post'><input name='nom1' value='val1'><input type='hidden' name='_csrfBuster' value='%{csrfToken}'></form></body></html>"

		csrfHappy := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok)
			return Text.fromHtml(str)
		}.toImmutable

		postFn := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			return Text.fromPlain("Post, nom1=" + req.body.form["nom1"])			
		}.toImmutable

		config.add(Route(`/get`, Text.fromPlain("Okay")))
		config.add(Route(`/post`, postFn, "POST"))

		config.add(Route(`/csrfHappy`, csrfHappy))
		config.add(Route(`/csrfNotFound`, Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input name='nom2' value='val2'></form></body></html>")))
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
