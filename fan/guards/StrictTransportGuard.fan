using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against protocol downgrade attacks and Cookie hijacking by setting a 'Strict-Transport-Security' HTTP response header that tells browsers to use HTTPS. 
** 
** The 'Strict-Transport-Security' HTTP header is support by all major browsers. 
** See [HTTP Strict Transport Security (HSTS)]`https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security` and
** [RFC 6797]`https://tools.ietf.org/html/rfc6797` for details. 
** 
**    Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
** 
** 
** 
** IoC Configuration
** *****************
** HSTS is disabled by default as you don't want to force your development environment into using HTTPS!
** To enable, contribute this class to the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config, IocEnv iocEnv) {
**       if (iocEnv.isProd)
**           config["strictTransport"] = StrictTransportGuard(5day)
**   }
** 
const class StrictTransportGuard : Guard {

	private const Str	hsts

	** Creates a 'StrictTransportGuard' instance.
	** 
	** - 'maxAge' - How long future requests to the domain should go over HTTPS.
	** - 'includeSubdomains' - If subdomains should also be HTTPS.
	** - 'preload' - Allow this domain to be included in browsers HSTS preload list. See `https://hstspreload.org/` for details.
	new make(Duration maxAge := 365day, Bool includeSubdomains := false, Bool preload := false) {
		hsts = "max-age=${maxAge.toSec}"
		if (includeSubdomains)
			hsts += "; includeSubDomains"
		if (preload)
			hsts += "; preload"
	}

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		httpRes.headers["Strict-Transport-Security"] = hsts
		return null
	}
}
