using afIoc
using afIocConfig::ApplicationDefaults
using afBounce
using afBedSheet
using concurrent::Actor

internal abstract class SleepSafeTest : Test {
	BedServer? 	server
	BedClient? 	client
	
	BedClient fireUp(Type[] mods := [,], [Str:Obj?]? appConfig := null) {
		Actor.locals["test.appConfig"] = appConfig
		server = BedServer(SleepSafeModule#.pod)
			.addModule(WebTestModule#)
			.addModules(mods)
			.startup
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
		req := (HttpRequest) scope.serviceByType(HttpRequest#)

		postFn := |->Text| {
			return Text.fromPlain("Post, nom=" + req.body.form["nom"])
		}.toImmutable

		post2Fn := |->Text| {
			val := null as Str
			req.parseMultiPartForm |nom, in| { if (nom == "nom") val = in.readAllStr }
			return Text.fromPlain("Post, nom=" + val)
		}.toImmutable

		config.add(Route(`/getPlain`,				Text.fromPlain("Okay")))
		config.add(Route(`/getHtml`,				Text.fromHtml ("Okay")))
		config.add(Route(`/post`,					postFn,  "POST"))
		config.add(Route(`/post2`,					post2Fn, "POST"))
	}

	@Contribute { serviceType=ApplicationDefaults# }
	Void contributeApplicationDefaults(Configuration config) {
		appConfig := ([Str:Obj?]?) Actor.locals["test.appConfig"]
		appConfig?.each |v, k| { config[k] = v }
	}

	Void onRegistryStartup(Configuration config) {
		config.remove("afIoc.logBanner",		"afIoc.silentBanner")
		config.remove("afIoc.logServices",		"afIoc.silentServices")
		config.remove("afIoc.logStartupTimes",	"afIoc.silentStartupTimes")
	}
	Void onRegistryShutdown(Configuration config) {
		config.remove("afIoc.sayGoodbye", "afIoc.silentBoodbye")
	}
}
