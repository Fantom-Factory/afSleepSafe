using afIoc::Inject
using afIocConfig::Config
using afBedSheet

** BedSheet middleware that invokes the Guards.
** 
** 'SleepSafeMiddleware' is contributed with the following:
** 
** pre>
** syntax: fantom
** 
** @Contribute { serviceType=MiddlewarePipeline# }
** Void contributeMiddleware(Configuration config, SleepSafeMiddleware middleware) {
**     config.set("SleepSafeMiddleware", middleware).after("afBedSheet.assets").before("afBedSheet.routes")
** }
** <pre
** 
** Assets are not purposely not protected to prevent HTTP sessions being loaded (potentially from a database) on *every* 
** request. Override Middleware ordering to change this behaviour.
**
const class SleepSafeMiddleware : Middleware {
	
	@Inject private const Log					log
	@Inject private const HttpRequest			req
	@Inject private const HttpResponse			res
	@Inject private const ResponseProcessors	resPros
	@Config	private const Int					rejectedStatusCode
	
	** The Guards used to protect / reject each HTTP request.
					const Guard[]				guards
	
	private new make(Type:Guard guards, |This| f) {
		f(this)		
		// note: we can inject just "Guard[]" when we upgrade to afIoc 3.0.8  
		this.guards = guards.vals
	}
	
	@NoDoc
	override Void service(MiddlewarePipeline pipeline) {
		denied := guards.eachWhile { it.guard(req, res) }
		
		if (denied != null)
			rejectSuspectedAttack(denied)
		else
			pipeline.service
	}
	
	** Hook to respond to failed Guard checks. 
	** Defaults to logging the msg (at warn level) and processes a 403 status.
	virtual Void rejectSuspectedAttack(Str msg) {
		log.warn(msg)
		resPros.processResponse(HttpStatus(rejectedStatusCode, msg))
	}
}
