using afIoc
using afIocConfig::ApplicationDefaults
using afBounce
using afBedSheet
using concurrent::Actor

internal abstract class SleepSafeTest : Test {
	BedServer? 	server
	BedClient? 	client
	
	BedClient fireUp([Str:Str?]? appConfig := null, Type? mod := null) {
		Actor.locals["test.appConfig"] = appConfig
		server = BedServer(SleepSafeModule#.pod)
			.addModule(WebTestModule#)
			{ if (mod != null) addModule(mod) }
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

		csrfHtml := "<!DOCTYPE html><html><body><form method='post' action='/post'><input name='nom' value='val1'><input type='hidden' name='_csrfToken' value='%{csrfToken}'></form></body></html>"

		csrfHappy := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok)
			return Text.fromHtml(str)
		}.toImmutable

		csrfCustomName := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("_csrfToken", "peanut").replace("val1", "val3")
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			echo(str)
			return Text.fromHtml(str)
		}.toImmutable

		postFn := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			return Text.fromPlain("Post, nom=" + req.body.form["nom"])
		}.toImmutable

		config.add(Route(`/get`,			Text.fromPlain("Okay")))
		config.add(Route(`/post`,			postFn, "POST"))

		config.add(Route(`/csrfHappy`, 		csrfHappy))
		config.add(Route(`/csrfNoForm`,		Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'></form></body></html>")))
		config.add(Route(`/csrfNotFound`,	Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='nom' value='val'></form></body></html>")))
		config.add(Route(`/csrfInvalid`,	Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='_csrfToken' value='XXXXXXXX'></form></body></html>")))
		config.add(Route(`/csrfCustomEnc`,	Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post' enctype='slimer/dude'><input type='hidden' name='_csrfToken' value='XXXXXXXX'><input type='hidden' name='nom' value='val4'></form></body></html>")))
		config.add(Route(`/csrfCustomName`,	csrfCustomName))
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
