using afIocConfig::Config
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against clickjacking by setting an 'X-Frame-Options' HTTP response header that tells browsers not to embed the page in a frame.
** 
** The 'X-Frame-Options' HTTP header is support by Internet Explorer 8, Firefox 3.6.9, Opera 10.50, Safari 4.0, Chrome 4.1.249.1042.
** 
** 
** 
** IoC Configuration
** *****************
** 
**   table:
**   afIocConfig Key             Value
**   --------------------------  ------------
**   'afSleepSafe.xFrameOptions'  Defines who's allowed to embed the page in a frame. Set to 'deny' to forbid any embedding or 'sameorigin' to allow embedding from the same origin (default).
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.xFrameOptions"] = "deny"
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove("xFrameOptions")
**   }
** 
const class XFrameOptionsGuard : Guard {
	
	@Config	private const Str? xFrameOptions
	
	private new make(|This| f) { f(this) }
	
	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xFrameOptions = xFrameOptions
		return null
	}
}
