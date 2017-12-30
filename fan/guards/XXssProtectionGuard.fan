using afIocConfig::Config
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against Cross Site Scripting (XSS) by setting an 'X-XSS-Protection' HTTP response header that tells browsers enable XSS filtering.
** 
**   X-XSS-Protection: 1; mode=block
** 
** Note that browsers usually enable XSS filtering by default, so to disable it use the 'xssProtectionEnable' config.
** 
** See [X-XSS-Protection on MDN]`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection` for details.
** 
** 
** 
** IoC Configuration
** *****************
** 
**   table:
**   afIocConfig Key                     Value
**   ----------------------------------  ------------
**   'afSleepSafe.xXssProtectionEnable'  Tells the browser to enable / disable XSS filtering. 
**   'afSleepSafe.xXssProtectionMode'    How the browser should prevent the attack. Defaults to 'block'.
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.xXssProtectionEnable"] = false
**       config["afSleepSafe.xXssProtectionMode"]   = null
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(XXssProtectionGuard#)
**   }
** 
const class XXssProtectionGuard : Guard {

	@Config	private const Bool xXssProtectionEnable
	@Config	private const Str? xXssProtectionMode
			private const Str  xXssProtection

	private new make(|This| f) {
		f(this)
		xXssProtection = xXssProtectionEnable ? "1" : "0"
		if (xXssProtectionEnable && xXssProtectionMode != null)
			xXssProtection += "; mode=${xXssProtectionMode}"
	}

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xXssProtection = xXssProtection
		return null
	}
}
