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

		csrfHtml := "<!DOCTYPE html><html><body><form method='post' enctype='application/x-www-form-urlencoded' action='/post'><input name='nom' value='val1'><input type='hidden' name='_csrfToken' value='%{csrfToken}'></form></body></html>"

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
			return Text.fromHtml(str)
		}.toImmutable

		csrfPlainTextHappy := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("val1", "val5").replace("application/x-www-form-urlencoded", "text/plain")
			return Text.fromHtml(str)
		}.toImmutable

		csrfPlainTextUnhappy := |->Text| {
			str := csrfHtml.replace("%{csrfToken}", "XXXXXX").replace("application/x-www-form-urlencoded", "text/plain")
			return Text.fromHtml(str)
		}.toImmutable

		csrfMultipartHappy := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("%{csrfToken}", tok).replace("val1", "val6").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		csrfMultipartUnhappy := |->Text| {
			str := csrfHtml.replace("%{csrfToken}", "XXXXXX").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		csrfUriHappy := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			tok := (Str) req.stash["afSleepSafe.csrfToken"]
			str := csrfHtml.replace("_csrfToken", "meh").replace("/post", "/post?_csrfToken=$tok").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2").replace("val1", "val6")
			return Text.fromHtml(str) 
		}.toImmutable

		csrfUriUnhappy := |->Text| {
			str := csrfHtml.replace("_csrfToken", "meh").replace("/post", "/post?_csrfToken=XXXXXXXX").replace("application/x-www-form-urlencoded", "multipart/form-data").replace("/post", "/post2")
			return Text.fromHtml(str)
		}.toImmutable

		postFn := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			return Text.fromPlain("Post, nom=" + req.body.form["nom"])
		}.toImmutable

		post2Fn := |->Text| {
			req := (HttpRequest) scope.serviceByType(HttpRequest#)
			val := null as Str
			req.parseMultiPartForm |nom, in| { if (nom == "nom") val = in.readAllStr }
			return Text.fromPlain("Post, nom=" + val)
		}.toImmutable

		config.add(Route(`/get`,					Text.fromPlain("Okay")))
		config.add(Route(`/post`,					postFn,  "POST"))
		config.add(Route(`/post2`,					post2Fn, "POST"))
		config.add(Route(`/csrfHappy`, 				csrfHappy))
		config.add(Route(`/csrfNoForm`,				Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'></form></body></html>")))
		config.add(Route(`/csrfNotFound`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='nom' value='val'></form></body></html>")))
		config.add(Route(`/csrfInvalid`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post'><input type='hidden' name='_csrfToken' value='XXXXXXXX'></form></body></html>")))
		config.add(Route(`/csrfCustomEnc`,			Text.fromHtml("<!DOCTYPE html><html><body><form method='post' action='/post' enctype='slimer/dude'><input type='hidden' name='_csrfToken' value='XXXXXXXX'><input type='hidden' name='nom' value='val4'></form></body></html>")))
		config.add(Route(`/csrfCustomName`,			csrfCustomName))
		config.add(Route(`/csrfPlainHappy`,			csrfPlainTextHappy))
		config.add(Route(`/csrfPlainUnhappy`,		csrfPlainTextUnhappy))
		config.add(Route(`/csrfMultipartHappy`,		csrfMultipartHappy))
		config.add(Route(`/csrfMultipartUnhappy`,	csrfMultipartUnhappy))
		config.add(Route(`/csrfUriHappy`,			csrfUriHappy))
		config.add(Route(`/csrfUriUnhappy`,			csrfUriUnhappy))
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
