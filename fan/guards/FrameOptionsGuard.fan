using afIocConfig::Config
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against clickjacking by setting an 'X-Frame-Options' HTTP response header that tells browsers not to embed the page 
** in a frame.
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
	override const Str protectsAgainst	:= "Clickjacking" 

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		if (frameOptions != null)

			// don't bother setting headers for non-HTML files
			// https://stackoverflow.com/questions/48151455/for-which-content-types-should-i-set-security-related-http-response-headers
			httpRes.onCommit |->| {
				contentType := httpRes.headers.contentType?.noParams?.toStr?.lower
				if (contentType == "text/html" || contentType == "application/xhtml+xml")
					httpRes.headers.xFrameOptions = frameOptions
			}

		return null
	}
}
