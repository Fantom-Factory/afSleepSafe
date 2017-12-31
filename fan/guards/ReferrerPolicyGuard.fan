using afIocConfig::Config
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against internal URL leakage by setting a 'Referrer-Policy' HTTP response header that tells browsers how and when to transmit the HTTP Referer (sic) header.
** 
**   Referrer-Policy: same-origin
** 
** See [Referrer-Policy on MDN]`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy` for details.
**
**  
** 
** IoC Configuration
** *****************
** 
**   table:
**   afIocConfig Key               Value
**   ----------------------------  ------------
**   'afSleepSafe.referrerPolicy'  Defines when the referrer header should be sent.
**
** Defaults to 'no-referrer, strict-origin-when-cross-origin' which disables referrers for browsers that don't support 'strict-origin-when-cross-origin'. See [Web Security Guidelines]`https://wiki.mozilla.org/Security/Guidelines/Web_Security#Referrer_Policy` for details.
**  
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.referrerPolicy"] = "no-referrer"
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(ReferrerPolicyGuard#)
**   }
** 
const class ReferrerPolicyGuard : Guard {

	@Config	private const Str? referrerPolicy
	
	private new make(|This| f) { f(this) }
	
	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.referrerPolicy = referrerPolicy
		return null
	}
}
