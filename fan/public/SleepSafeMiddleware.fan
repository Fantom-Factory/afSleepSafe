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
**     config.set("afSleepSafe.guards", middleware).after("afBedSheet.assets").before("afBedSheet.routes")
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
	
	@NoDoc
	new make(Type:Guard guards, |This| f) {
		f(this)		
		// note: we can inject just "Guard[]" when we upgrade to afIoc 3.0.8  
		this.guards = guards.vals
	}
	
	@NoDoc
	override Void service(MiddlewarePipeline pipeline) {
		if (shouldGuardRequest(req)) {
			denied := guards.eachWhile { it.guard(req, res) }		
			if (denied != null)
				return rejectSuspectedAttack(denied)
		}
		pipeline.service
	}
	
	** Override hook to optionally exempt HTTP requests from being guarded by SleepSafe.
	** Sometimes you want to exclude URLs from being processed, this override hook lets you do that by optionally returning 'false'.
	** 
	** This method defaults to returning 'true'.
	virtual Bool shouldGuardRequest(HttpRequest httpReq) { true }
	
	** Override hook to respond to failed Guard checks. 
	** Defaults to logging the msg (at warn level) and processes a 403 status.
	virtual Void rejectSuspectedAttack(Obj errObj) {
		msg := errObj.toStr
		log.warn(msg)
		resPros.processResponse(HttpStatus(rejectedStatusCode, msg))
	}
}
