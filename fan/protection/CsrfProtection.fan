using afIoc::Inject
using afIocConfig::Config
using afBedSheet
using util::Random

** Protects against CSRF attacks by enforcing an customisable [Encrypted Token Pattern]`https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern` strategy.
**
** 
**  
** Overview
** ********
** Cross Site Request Forgeries (CSRF) are a very specific type of attack vector.
** 
** Think of it as someone stealing your application URLs such as 'http://example.com/logout' or 'http://example.com/buyProduct/XXXXXX'
** and tricking people in to clicking them, either though emails, fake HTML image links ('<img src="http://example.com/buyProduct/XXXXXX">'),
** or other means. If the user happens to be logged in to your site, then the browser will happily send the fake request and 
** **BOOM** before the user realises it, he's just bought a [Sex Doll]`https://www.amazon.co.uk/sexdoll/dp/B077S3J1SP`!
** 
** But it's not just HTTP 'GET' requests, browsers will happily 'POST' form data across domains too. In fact, 'GET' requests 
** should **never** affect server state, they should just *get* content. Any kind of logout, delete, or buy action should be 
** performed over a 'POST' request with for data. So now we just just need to protect 'POST' requests.
** 
** To protect against CSRFs, SleepSafe generates a unique token per HTTP request that should be embedded in every form. 
** This token is an encrypted form of a timestamp, the user's session ID (if one exists) and any other information you care to add.
** When the form is submitted, the token is retrieved, decrypted, and values compared against the user's existing credentials.
** The request is rejected should any values mis-match and, optionally, if the token has since expired (expiry defaults to 1 hour). 
** 
** To circumnavigate this, an attacker would have to steal a CSRF token value from an already authenticated user. 
** The only way to do this is by either packet sniffing or injecting their own scripts via Cross Site Scripting (XSS) and 
** immediately tricking a targeted user. All of which is outside of the scope of CSRF protection. 
** 
** Note that encryption is performed with 128 bit AES which would take my dev machine 100 septillion (10^24) years to crack 
** with a standard brute force attack algorithm.  
** 
** 
** 
** Specifics
** *********
** When rendering a HTML form you must include the following input:
** 
**   syntax: html
**   <input type="hidden" name="_csrfBuster" value="XXXX-XXXX-XXXX-XXXX">
** 
** where 'value' is obtained from:
** 
**   syntax: fantom
**   token := httpRequest.stash["afSleepSafe.csrfToken"]
** 
** SleepSafe adds the CSRF token to the stash at the start of every request.
** 
** When the form is submitted SleepSafe inspects all POST requests with a content type of either:
**  - 'application/x-www-form-urlencoded'
**  - 'multipart/form-data'
**  - 'text/plain'
** and checks and validates the '_csrfBuster' token value.
** 
** Other content types can not be submitted by HTML forms and as such, are not subject to CSRF attacks and are not checked by
** SleepSafe.
** 
** 
** 
** Origin HTTP Request Header
** ==========================
** SleepSafe can optionally skip token checks if the request contains an 'Origin' header that matches the BedSheet configured host. 
** 'Origin' is a browser controller request header that can be trusted within the context of CSRF attacks. 
** If the 'Origin' header matches the BedSheet host, then the request was initiated by content from this server and the request
** can be trusted.
** 
** Note that the default BedSheet host of 'localhost' is not trusted and requests with such 'Origin' values are still subject
** to CSRF token checks.    
** 
** This is disabled by default as *not* checking the CSRF token could leave you vulnerable to other non-CSRF attacks.
**
**  
** 
** Custom HTTP Request Headers
** ===========================
** SleepSafe can optionally skip token checks if the request contains a named custom header, such as 'X-Requested-With: XMLHttpRequest'.
** 
** That's because custom headers can only be set via [XMLHttpRequest]`https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader`
** and 'XMLHttpRequests' are subject to the [Same Origin Policy]`https://en.wikipedia.org/wiki/XMLHttpRequest#Cross-domain_requests`.
** Hence it is impossible for an attacker to submit custom headers in a CSRF attack.
** 
** This is disabled by default as *not* checking the CSRF token could leave you vulnerable to other non-CSRF attacks.
** 
** 
** 
** Multi-Part Form Uploads
** =======================
** SleepSafe will parse multipart form-data looking for the CSRF token. But in doing so note that the entire form data will be 
** parsed twice, once by SleepSafe and again by your application - which may represent an overhead.
** 
** If this is not desirable, then you may also append the CSRF token as a URL query parameter. Although this may constitute a 
** minor security flaw / inconvenience as request URLs are often logged.
** 
** 
** 
** Configuration
** *************
** 
**   table:
**   afIocConfig Key                 Value
**   ---------------------------     ------------
**   'afSleepSafe.csrfTokenName'     Name of the posted form field that holds the CSRF token. Defaults to '_csrfToken'.
**   'afSleepSafe.csrfTokenTimeout'  How long CSRF tokens have to live. Set to 'null' to disable timeouts. Defaults to '60min'.
** 
** Example:
** 
**   syntax: fantom 
**   using afIoc::Contribute 
**   using afIoc::Configuration
**   using afIocConfig::ApplicationDefaults
** 
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.csrfTokenName"]    = "clickFast"
**       config["afSleepSafe.csrfTokenTimeout"] = 2sec
**   }
** 
** To disable, remove this class from the SleepSafeMiddleware configuration:
** 
**   syntax: fantom 
**   using afIoc::Contribute 
**   using afIoc::Configuration
**   using afIocConfig::SleepSafeMiddleware
** 
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove("csrf")
**   }
** 
const class CsrfProtection : Protection {

	@Inject	private const HttpRequest			httpReq
	@Inject	private const HttpResponse			httpRes
	@Inject	private const HttpSession			httpSes
	@Inject	private const CsrfCrypto			crypto
	@Inject	private const CsrfTokenGeneration	genFuncs
	@Inject	private const CsrfTokenValidation	valFuncs
	static	private const MimeType				mimeAppForm		:= MimeType("application/x-www-form-urlencoded")
	static	private const MimeType				mimeTextPlain	:= MimeType("text/plain")

	@Config	{ id="afSleepSafe.csrfTokenName" }
			private const Str					tokenName

	private new make(|This| f) { f(this) }

	@NoDoc
	override Str? protect(HttpRequest httpReq, HttpResponse httpRes) {
		httpReq.stash["afSleepSafe.csrfToken"]		= generateToken
		httpReq.stash["afSleepSafe.csrfTokenFn"]	= #generateToken.func.bind([this])		

		return fromVunerableUrl ? doProtection : null
	}

	private Str? doProtection() {
		contentType := httpReq.headers.contentType.noParams
		if (contentType == mimeAppForm || contentType == mimeTextPlain) {
			
			form := httpReq.body.form
			if (form == null)
				return csrfErr("No form data")
			
			csrfToken := form[tokenName]
			if (csrfToken == null)
				return csrfErr("Form does not contain '${tokenName}' key")
			
			hash := null as Str:Obj?
			try {
				fanCode	:= crypto.decode(csrfToken)
				fanObj	:= fanCode.toBuf.readObj
				hash	 = (Str:Obj?) fanObj
			} catch (Err err)
				return csrfErr("Invalid '${tokenName}' value")
			
			try
				valFuncs.call(hash)
			catch (Err err)
				return csrfErr(err.msg)
		}
		return null
	}
	
	private Bool fromVunerableUrl() {
		if (httpReq.httpMethod == "POST") {
			contentType := httpReq.headers.contentType.noParams.toStr.lower
			if (contentType == "application/x-www-form-urlencoded" ||
				contentType == "text/plain" ||
				contentType == "multipart/form-data")
				return true
		}
		return false
	}
	
	private Str generateToken() {
		hash := [:] { ordered = true }
		genFuncs.call(hash)
		code := Buf().writeObj(hash).flip.readAllStr
		return crypto.encode(code)
	}
	
	private Str csrfErr(Str msg) {
		"Suspected CSRF attack - $msg"
	}
}

const class CsrfTokenGeneration {
	private const |[Str:Obj?]|[] funcs

	private new make(|[Str:Obj?]|[] funcs) {
		this.funcs = funcs
	}
	
	Void call(Str:Obj? hash) {
		funcs.each { it.call(hash) }
	}
}

const class CsrfTokenValidation {
	private const |[Str:Obj?]|[] funcs

	private new make(|[Str:Obj?]|[] funcs) {
		this.funcs = funcs
	}

	Void call(Str:Obj? hash) {
		funcs.each { it.call(hash) }
	}
}
