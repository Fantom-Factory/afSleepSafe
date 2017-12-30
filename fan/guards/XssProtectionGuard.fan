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
**   afIocConfig Key                    Value
**   ---------------------------------  ------------
**   'afSleepSafe.xssProtectionEnable'  Tells the browser to enable / disable XSS filtering. Defaults to 'true'.
**   'afSleepSafe.xssProtectionMode'    How the browser should prevent the attack. Defaults to 'block'.
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.xssProtectionEnable"] = false
**       config["afSleepSafe.xssProtectionMode"]   = null
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(XssProtectionGuard#)
**   }
** 
const class XssProtectionGuard : Guard {

	@Config	private const Bool xssProtectionEnable
	@Config	private const Str? xssProtectionMode
			private const Str  xssProtection

	private new make(|This| f) {
		f(this)
		xssProtection = xssProtectionEnable ? "1" : "0"
		if (xssProtectionEnable && xssProtectionMode != null)
			xssProtection += "; mode=${xssProtectionMode}"
	}

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xXssProtection = xssProtection
		return null
	}
}
