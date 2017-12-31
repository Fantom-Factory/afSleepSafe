using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guard against malicious attacks by inspecting HTTP requests.
** 
** Once implemented, contribute it to 'SleepSafeMiddleware':
** 
**   syntax: fantom
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config[MyGuard#] = config.build(MyGuard#)
**   }
** 
const mixin Guard {

	** Return what this Guard protects against. Used in startup logging.
//	virtual 
	abstract Str protectsAgainst()
	//{ "" }
	
	** Called at the start of HTTP request. Return an error message to reject the request.  
	abstract Str? guard(HttpRequest req, HttpResponse res)
	
}
