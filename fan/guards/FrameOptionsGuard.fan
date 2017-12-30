using afIocConfig::Config
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against clickjacking by setting an 'X-Frame-Options' HTTP response header that tells browsers not to embed the page in a frame.
** 
**   X-Frame-Options: SAMEORIGIN
** 
** See [X-Frame-Options on MDN]`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options` and [RFC 7034]`https://tools.ietf.org/html/rfc7034` for details.
** 
** 
** 
** IoC Configuration
** *****************
** 
**   table:
**   afIocConfig Key             Value
**   --------------------------  ------------
**   'afSleepSafe.frameOptions'  Defines who's allowed to embed the page in a frame. Set to 'DENY' to forbid any embedding, 'SAMEORIGIN' to allow embedding from the same origin (default), or 'ALLOW-FROM https://example.com/' to specify a host.
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.frameOptions"] = "deny"
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(FrameOptionsGuard#)
**   }
** 
const class FrameOptionsGuard : Guard {
	
	@Config	private const Str? frameOptions
	
	private new make(|This| f) { f(this) }
	
	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xFrameOptions = frameOptions
		return null
	}
}
