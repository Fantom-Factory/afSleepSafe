using afIoc::Inject
using afIocConfig::Config
using afBedSheet

** BedSheet middleware that is run before any BedSheet routing.  
const class SleepSafeMiddleware : Middleware {
	
	@Inject private const Log					log
	@Inject private const HttpRequest			req
	@Inject private const HttpResponse			res
	@Inject private const ResponseProcessors	resPros
	@Config	private const Int					deniedStatusCode

	
	const Guard[] guards
	
	new make(Type:Guard guards, |This| f) {
		// note: we can inject just "Guard[]" when we upgrade to afIoc 3.0.8  
		this.guards = guards.vals
		f(this)
		
		msg := "\n\n"
		msg += "SleepSafe is protecting your web application against:\n"
		msg += " - Clickjacking with SafeFrameOptions\n"
		log.info(msg)
	}
	
	override Void service(MiddlewarePipeline pipeline) {
		denied := guards.eachWhile { it.guard(req, res) }
		
		if (denied != null) {
			log.warn(denied)	// TODO fandoc this warn
			resPros.processResponse(HttpStatus(deniedStatusCode, denied))
		} else
			pipeline.service
	}
}
