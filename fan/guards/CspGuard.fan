using afIocConfig::Config
using afIocConfig::ConfigSource
using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

** Guards against Cross Site Scripting (XSS) by setting an 'Content-Security-Policy' HTTP response header that tells browsers to restrict where content can be loaded from.
**
**   Content-Security-Policy: default-src 'self'; font-src 'self' https://fonts.googleapis.com/; object-src 'none'
**
** See `https://content-security-policy.com/` and [Content-Security-Policy on MDN]`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy` for details.
**
** By default, Sleep Safe sets the following content directives:
**
**   Content-Security-Policy:
**       default-src 'self';
**       base-uri 'self';
**       form-action 'self';
**       frame-ancestors 'self';
**       object-src 'none';
**       report-uri /_sleepSafeCspViolation;
**
** Which essentially locks all content down to that served by the BedSheet server and disables object tags.
**
** SleepSafe also sets up a BedSheet Route ('report-uri') that browsers can report violations to.
** The default implementation logs a pretty printed version of the report JSON.
**
** The default strategy is a good base to start with. You can then upgrade the directives as and when you need to.
** Although beware of inline scripts and style tags, as these will also be disabled. See [Implementing Content Security Policy]`https://hacks.mozilla.org/2016/02/implementing-content-security-policy/` for details.
**
** The reporting mechanism is good for development, but you may want to turn it off for production as browser add-ons can
** cause violations, flooding your server.
**
**
**
** Ioc Configuration
** *****************
**
**   table:
**   afIocConfig Key              Value
**   ---------------------------  ------------
**   'afSleepSafe.csp.XXXX'       Any config starting with 'afSleepSafe.csp.' (note the trailing dot) is taken as a CSP directive and used as is. Set to 'null' to remove a directive.
**   'afSleepSafe.cspReportOnly'  If 'true' then the 'Content-Security-Policy-Report-Only' header is set, which doesn't block anything but still sends violation reports. Defaults to 'false'.
**   'afSleepSafe.cspReportFn'    The reporting function (immutable) that's invoked with the browsers violation JSON. Set to 'null' to disable report handling and the default BedSheet route.
**
** Example:
**
**   syntax: fantom
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       // configure CSP
**       config["afSleepSafe.cspReportOnly"]   = true
**       config["afSleepSafe.cspReportFn"]     = |Str:Obj? reportJson| { echo(reportJson) }.toImmutable
**
**       // set CSP directives
**       config["afSleepSafe.csp.default-src"] = "'none'"
**       config["afSleepSafe.csp.font-src"]    = "'self' https://fonts.googleapis.com/"
**   }
**
** To prevent CSP violations from being logged on the server, remove either (or both) of the following ApplicationDefaults:
** 
**   syntax: fantom
**   config.remove("afSleepSafe.csp.report-uri")
**   config.remove("afSleepSafe.cspReportFn")
** 
** To disable CSP, remove this class from the 'SleepSafeMiddleware' configuration:
**
**   syntax: fantom
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(CspGuard#)
**   }
**
const class CspGuard : Guard {

	private const Str? csp
	@Config { id="afSleepSafe.cspReportOnly" }
	private const Bool reportOnly

	** The 'Content-Security-Protection' directives that get passed to the browser
	const Str:Str directives

	@NoDoc
	override const Str protectsAgainst	:= "XSS"

	private new make(ConfigSource configSrc, |This| f) {
		f(this)

		directives := Str:Str[:]
		configSrc.config.each |val, key| {
			if (key.startsWith("csp.") || key.startsWith("afSleepSafe.csp.")) {
				if (key.startsWith("afSleepSafe."))
					key = key["afSleepSafe.".size..-1]
				if (key.startsWith("csp."))
					key = key["csp.".size..-1]
				if (val != null)
					directives[key] = val.toStr
			}

		}
		directives2 := Str:Str[:] { it.ordered = true }
		directives.keys.sort.each { directives2[it] = directives[it] }
		this.directives = directives2
		this.csp = directives2.join("; ") |val, key| { "${key} ${val}" }.trimToNull
	}

	@NoDoc
	override Str? guard(HttpRequest httpReq, HttpResponse httpRes) {
		if (csp != null) {
			// set the headers at the start of the request so other code may add or manipulate it
			if (reportOnly)
				httpRes.headers["Content-Security-Policy-Report-Only"] = csp
			else
				httpRes.headers["Content-Security-Policy"] = csp

			// don't bother setting the CSP header for non-HTML files
			// https://stackoverflow.com/questions/48151455/for-which-content-types-should-i-set-security-related-http-response-headers
			httpRes.onCommit |->| {
				contentType := httpRes.headers.contentType?.noParams?.toStr?.lower
				if (contentType == "text/html" || contentType == "application/xhtml+xml")
					return

				// if it's not a HTML page, then remove the headers
				if (reportOnly) {
					httpRes.headers["Content-Security-Policy-Report-Only"] = null
				} else {
					httpRes.headers["Content-Security-Policy"] = null
				}
			}
		}

		return null
	}
}
