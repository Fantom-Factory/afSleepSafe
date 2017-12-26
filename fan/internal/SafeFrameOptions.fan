using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Protects against clickjacking by setting an 'X-Frame-Options' HTTP header that tells browsers not to embed the page in a frame.
** 
**   table:
**   --------------------------  ------------
**   Helps prevent attacks from  Clickjacking
**   Supported browsers          Internet Explorer 8, Firefox 3.6.9, Opera 10.50, Safari 4.0, Chrome 4.1.249.1042
** 
** 
** 
** Configuration
** *************
** 
**   table:
**   afIocConfig Key             Value
**   --------------------------  ------------
**   'afSleepSafe.frameOptions'  Defines who's allowed to embed the page in a frame. Set to 'deny' to forbid any embedding, 'sameorigin' to allow embedding from the same origin (default), or 'null' to disable.
** 
** Example:
** 
**   syntax: fantom 
**   using afIocConfig::ApplicationDefaults
** 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.frameOptions"] = "deny"
**   }
** 
const class SafeFrameOptions : Protection {
	
	private const Str frameOptions
	
	internal new make(Str frameOptions) {
		this.frameOptions = frameOptions
	}
	
	@NoDoc
	override Str? protect(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xFrameOptions = frameOptions
		return null
	}
}
