using afIoc::Inject
using afIocConfig::Config
using afIocConfig::ConfigSource
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse
using afBedSheet::HttpSession

** Guards against Session hijacking by caching browser user-agent parameters and checking them on each request. 
** The session is dropped and request rejected should the parameters change.  
** 
** 
** 
** IoC Configuration
** *****************
** 
**   table:
**   afIocConfig Key                     Value
**   ----------------------------------  ------------
**   'afSleepSafe.sessionHijackHeaders'  CSV of request headers that are to be cached and compared. Defaults to 'User-Agent, Accept-Language'.
**   'afSleepSafe.sessionHijackEncrypt'  If 'true' (the default) then a hash of the header parameters is cached, and not the actual parameter values themselves. This is a security measure against the server / database being breached.
** 
** Example:
** 
**   syntax: fantom 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.csrfTokenName"]    = "clickFast"
**       config["afSleepSafe.csrfTokenTimeout"] = 2sec
**   }
** 
** To disable, remove this class from the 'SleepSafeMiddleware' configuration:
** 
**   syntax: fantom 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(SessionHijackGuard#)
**   }
** 
const class SessionHijackGuard : Guard {

	@Inject	private const HttpSession	httpSes
	@Config	{ id="afSleepSafe.sessionHijackEncrypt" }
			private const Bool			encrypt			
			private const Str[]			headers

	private new make(ConfigSource configSrc, |This| f) {
		f(this)
		csv		:= (Str) configSrc.get("afSleepSafe.sessionHijackHeaders", Str#)
		headers = csv.split(',').exclude { it.isEmpty }		
	}
	
	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		if (!httpSes.exists)
			return null
		
		map := Str:Str[:] { ordered = true }
		headers.each |header| {
			map[header] = httpReq.headers.val.get(header, "")
		}
		
		hash := map.join(", ")
		if (encrypt)
			hash = hash.toBuf.toDigest("SHA-1").toBase64Uri
		
		reject := null as Str
		if (httpSes.containsKey("afSleepSafe.sessionHash")) {
			oldHash := httpSes["afSleepSafe.sessionHash"]
			if (oldHash != hash) {
				httpSes.delete
				return "Suspected Cookie Hijacking - Session parameters have changed: $oldHash != $hash"
			}
		}

		httpSes["afSleepSafe.sessionHash"] = hash
		
		// if the session is subsequently created in this request, then the user-agent params won't be cached until the next
		// request! This gives a would be attacker a 1-request chance to sneak in right at the start. But given header values
		// are easy to forge, any serious attack would easily bypass this Guard anyway.  
		
		return reject
	}
}
