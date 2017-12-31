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
			private const Guard[]				guards
	
	private new make(Type:Guard guards, |This| f) {
		// note: we can inject just "Guard[]" when we upgrade to afIoc 3.0.8  
		this.guards = guards.vals
		f(this)
		
		msg := "\n\n"
		msg += "SleepSafe is protecting your web application against:\n"
		msg += " - Clickjacking with SafeFrameOptions\n"
		log.info(msg)
	}
	
	@NoDoc
	override Void service(MiddlewarePipeline pipeline) {
		denied := guards.eachWhile { it.guard(req, res) }
		
		if (denied != null)
			respondToSuspectedAttack(denied)
		else
			pipeline.service
	}
	
	** Hook to respond to failed Guard checks. 
	** Defaults to logging the msg (at warn level) and processes a 403 status.
	virtual Void respondToSuspectedAttack(Str msg) {
		log.warn(msg)
		resPros.processResponse(HttpStatus(deniedStatusCode, msg))
	}
}
