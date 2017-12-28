using afIoc::Inject
using afIocConfig::Config
using afBedSheet

internal const class SleepSafeMiddleware : Middleware {
	
	@Inject private const Log					log
	@Inject private const HttpRequest			req
	@Inject private const HttpResponse			res
	@Inject private const ResponseProcessors	resPros
	@Config	private const Int					deniedStatusCode

	
	const Protection[] protection
	
	new make(Protection[] protection, |This| f) {
		this.protection = protection
		f(this)
		
		msg := "\n\n"
		msg += "SleepSafe is protecting your web application against:\n"
		msg += " - Clickjacking with SafeFrameOptions\n"
		log.info(msg)
	}
	
	override Void service(MiddlewarePipeline pipeline) {
		denied := protection.eachWhile { it.protect(req, res) }
		
		if (denied != null) {
			log.warn(denied)
			resPros.processResponse(HttpStatus(deniedStatusCode, denied))
		} else
			pipeline.service
	}
}
