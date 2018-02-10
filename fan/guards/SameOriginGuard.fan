using afIoc::Inject
using afIocConfig::ConfigSource
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse
using afBedSheet::BedSheetServer

** Guards against CSRF attacks by checking that the 'Referer' or 'Origin' HTTP header matches the 'Host'.
** 
** The idea behind the same origin check is that standard form POST requests should originate from the same server.
** So the 'Referer' and 'Origin' HTTP headers are checked to ensure they match the server host. 
** The 'Host' parameter is determined from [BedSheetServer.host()]`afBedSheet::BedSheetServer.host` and is usually picked up
** from the 'BedSheetConfigIds.host' config value.
** 
** Requests are also denied if neither the 'Referer' nor 'Origin' HTTP header are present. 
** 
** See [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet]`https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Verifying_Same_Origin_with_Standard_Headers` for details.
** 
** 
** 
** Ioc Configuration
** *****************
** 'SameOriginGuard' is disabled by default as a referrer policy is preferred. 
** For if a 'no-referrer' policy is enforced (either explicitly or as an older browser fall back) then, more than likely, this 
** guard will fail!
**   
** To enable, contribute this class to the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config[SameOriginGuard#] = config.build(SameOriginGuard#)
**   }
**
** Then to configure an origin whitelist:
** 
**   table:
**   afIocConfig Key                    Value
**   ---------------------------------  ------------
**   'afSleepSafe.sameOriginWhitelist'  A CSV of alternative allowed origins.
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.sameOriginWhitelist"] = "http://domain1.com, http://domain2.com"
**   }
** 
** To configure the BedSheet host:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afBedSheet.host"] = `https://example.com`
**   }
** 
const class SameOriginGuard : Guard {

	@Inject	private const BedSheetServer	bedServer
			private const Uri[]				whitelist
	
	private new make(ConfigSource configSrc, |This| f) {
		f(this)
		csv		 := (Str) configSrc.get("afSleepSafe.sameOriginWhitelist", Str#)
		whitelist = csv.split(',').map { Uri(it, false) }.exclude { it == null || it.toStr.isEmpty }
	}

	@NoDoc
	override const Str protectsAgainst	:= "CSRF" 

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		if (CsrfTokenGuard.fromVunerableUrl(httpReq)) {
			host := bedServer.host

			referrer := httpReq.headers.referrer?.plus(`/`)	// delete the path component
			// referrer is optional and may be relative - see https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.36
			if (referrer != null && referrer.isAbs) {
				if (host != referrer && !whitelist.contains(referrer))
					return csrfErr("Referrer does not match Host: ${referrer} != ${host}" + (whitelist.isEmpty ? "" : ", " + whitelist.join(", ")))
			}
			
			origin := httpReq.headers.origin?.plus(`/`)	// delete any path component (not that there should be any)
			if (origin != null) {
				if (host != origin && !whitelist.contains(origin))
					return csrfErr("Origin does not match Host: ${origin} != ${host}" + (whitelist.isEmpty ? "" : ", " + whitelist.join(", ")))
			}

			if (referrer == null && origin == null)
				return csrfErr("HTTP request contains neither a Referrer nor an Origin header")
		}
		return null
	}
	
	private Str csrfErr(Str msg) {
		"Suspected CSRF attack - $msg"
	}
}
