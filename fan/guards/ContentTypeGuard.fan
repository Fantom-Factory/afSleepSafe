using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against dodgy Content-Type sniffing by setting a 'X-Content-Type-Options' HTTP response header that tells browsers 
** to trust the 'Content-Type' header. 
** 
**    X-Content-Type-Options: nosniff
** 
** See [X-Content-Type-Options on MDN]`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options` for details.
**  
** 
** 
** IoC Configuration
** *****************
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(ContentTypeGuard#)
**   }
** 
const class ContentTypeGuard : Guard {

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers.xContentTypeOptions = "nosniff"
		return null
	}
}
