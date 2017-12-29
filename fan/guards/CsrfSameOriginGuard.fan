using afIoc::Inject
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
** Requests are also denied if neither the 'Referer' and 'Origin' HTTP header are present. 
** 
** See [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet]`https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Verifying_Same_Origin_with_Standard_Headers` for details.
** 
** 
** 
** Ioc Configuration
** *****************
** 
** To configure the BedSheet host:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.xFrameOptions"] = "deny"
**   }
** 
** To disable CSRF referrer checking, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove("csrfSameOrigin")
**   }
** 
const class CsrfSameOriginGuard : Guard {

	@Inject	private const BedSheetServer bedServer

	private new make(|This| f) { f(this) }

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		if (CsrfTokenGuard.fromVunerableUrl(httpReq)) {
			host := bedServer.host

			referrer := httpReq.headers.referrer?.plus(`/`)	// delete the path component
			if (referrer != null && referrer.isAbs) {
				if (host != referrer)
					return "Suspected CSRF attack - Referrer does not match Host: ${referrer} != ${host}"
			}
			
			origin := httpReq.headers.origin?.plus(`/`)	// delete any path component (not that there should be any)
			if (origin != null && origin.isAbs) {
				if (host != origin)
					return "Suspected CSRF attack - Origin does not match Host: ${origin} != ${host}"
			}
			
			if (referrer == null && origin == null)
				return "Suspected CSRF attack - HTTP request contains neither a Referrer nor an Origin header"
		}
		return null
	}
}
