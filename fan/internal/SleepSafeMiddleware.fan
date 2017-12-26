using afIoc::Inject
using afBedSheet

internal const class SleepSafeMiddleware : Middleware {
	
	@Inject private const Log			log
	@Inject private const HttpRequest	req
	@Inject private const HttpResponse	res
	
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
		
		protection.each {
			it.protect(req, res)
		}
		
		// 403 - Forbidden
		// log str
		// text/html application/xhtml
	}
}
