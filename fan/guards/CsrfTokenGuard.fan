using afIoc::Inject
using afIocConfig::Config
using afBedSheet

** Guards against CSRF attacks by enforcing an customisable [Encrypted Token Pattern]`https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern` strategy.
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
** To protect against CSRFs, SleepSafe generates a unique token per HTTP request that should be embedded in every HTML form.
** This token is an encrypted hash of a timestamp, the user's session ID (if one exists) and any other information you care to add.
** When the HTML form is submitted, the token is retrieved, decrypted, and values compared against the user's existing credentials.
** The request is rejected should any values mis-match and, optionally, if the token has since expired (expiry defaults to 1 hour).
**
** To circumnavigate this, an attacker would have to steal a CSRF token value from an already authenticated user.
** The only way to do this is by either packet sniffing or injecting their own scripts via Cross Site Scripting (XSS) and
** immediately tricking a targeted user. All of which is hard to do over HTTPS and is outside of the scope of CSRF protection.
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
**   <input type="hidden" name="_csrfToken" value="XXXX-XXXX-XXXX-XXXX">
**
** where 'value' is a 'Str' obtained from:
**
**   syntax: fantom
**   token := httpRequest.stash["afSleepSafe.csrfTokenFn"]->call()
**
** SleepSafe adds the CSRF token generation function to the stash at the start of every request.
**
** Note that [FormBean]`pod:afFormBean` will automatically add the hidden input, complete with token, to every rendered form.
**
** When the HTML form is submitted SleepSafe inspects all POST requests with a content type of:
**  - 'application/x-www-form-urlencoded'
**  - 'multipart/form-data'
**  - 'text/plain'
**
** and checks and validates the '_csrfToken' token value.
**
** Other content types can not be submitted by HTML forms and as such, are not subject to CSRF attacks, and are not checked by
** SleepSafe.
**
**
**
** Multi-Part Form Uploads
** =======================
** SleepSafe will parse multipart form-data looking for the CSRF token. But in doing so note that the entire HTTP Request body
** (form data) will be cached in memory and parsed twice, once by SleepSafe and again by your application - which may represent an overhead.
**
** If this is not desirable, then you may also append the CSRF token as a URL query parameter. Although this may constitute a
** minor security flaw / inconvenience as request URLs are often logged by applications and proxies.
**
**
**
** Ioc Configuration
** *****************
**
**   table:
**   afIocConfig Key                 Value
**   ------------------------------  ------------
**   'afSleepSafe.csrfTokenName'     Name of the posted form field that holds the CSRF token. Defaults to '_csrfToken'.
**   'afSleepSafe.csrfTokenTimeout'  How long CSRF tokens have to live. Set to 'null' to disable timeouts. Defaults to '61min' to ensure user sessions time out before tokens.
**   'afSleepSafe.csrfPassPhrase'    The pass phrase used to generate the encryption secret key. Generated CSRF tokens can only be used across server restarts if this value is set. If 'null' (default) then a random pass phrase is generated each time the sever starts.
**
** Example:
**
**   syntax: fantom
**   @Contribute { serviceType=ApplicationDefaults# }
**   Void contributeAppDefaults(Configuration config) {
**       config["afSleepSafe.csrfTokenName"]    = "clickFast"
**       config["afSleepSafe.csrfTokenTimeout"] = 2sec
**       config["afSleepSafe.csrfPassPhrase"]   = "Fantom Rocks!"
**   }
**
** To disable CSRF checking, remove this class from the 'SleepSafeMiddleware' configuration:
**
**   syntax: fantom
**   @Contribute { serviceType=SleepSafeMiddleware# }
**   Void contributeSleepSafeMiddleware(Configuration config) {
**       config.remove(CsrfTokenGuard#)
**   }
**
** To add custom data to the CSRF token hash:
**
**   @Contribute { serviceType=CsrfTokenGeneration# }
**   private Void contributeCsrfTokenGeneration(Configuration config) {
**       config["user"] = |Str:Obj? hash| {
**           hash["user"] = "Princess Daisy"
**       }
**   }
**
** Then to verify the custom data in the token hash:
**
**   @Contribute { serviceType=CsrfTokenValidation# }
**   private Void contributeCsrfTokenValidation(Configuration config) {
**       config["user"] = |Str:Obj? hash| {
**           if (hash.containsKey("user"))
**               if (hash["user"] != "Princess Daisy")
**                   throw Err("User is not a Princess!")
**       }
**   }
**
** Any error thrown will be picked up by SafeSheet and converted to a '403 Forbidden' response.
**
const class CsrfTokenGuard : Guard {

	@Inject	private const CsrfCrypto			crypto
	@Inject	private const CsrfTokenGeneration	genFuncs
	@Inject	private const CsrfTokenValidation	valFuncs
	static	private const MimeType				mimeApplication	:= MimeType("application/x-www-form-urlencoded")
	static	private const MimeType				mimePlainText	:= MimeType("text/plain")
	static	private const MimeType				mimeMultipart	:= MimeType("multipart/form-data")

	@Config	{ id="afSleepSafe.csrfTokenName" }
			private const Str					tokenName

	private new make(|This| f) { f(this) }

	@NoDoc
	override const Str protectsAgainst	:= "CSRF"

	@NoDoc
	override Obj? guard(HttpRequest httpReq, HttpResponse httpRes) {
		// let's not do crypo stuff on *every* request but rather, only when we need it
		// most requests will be for images, static pages, etc, and only rarely will we render a form
		// httpReq.stash["afSleepSafe.csrfToken"]	= generateToken()
		// httpReq.stash["afSleepSafe.csrfTokenFn"]	= #generateToken.func.bind([this])

		httpReq.stash["afSleepSafe.csrfTokenFn"] = |->Str| {
			// cache token in the stash
			// delete the token to force the fn to generate a new token
			httpReq.stash.getOrAdd("afSleepSafe.csrfToken") { generateToken }
		}

		return fromVunerableUrl(httpReq) ? doProtection(httpReq, httpRes) : null
	}

	private Obj? doProtection(HttpRequest httpReq, HttpResponse httpRes) {
		csrfToken := null as Str

		if (httpReq.url.query.containsKey(tokenName)) {
			csrfToken = httpReq.url.query[tokenName]
		} else {
			contentType := httpReq.headers.contentType.noParams
			if (contentType == mimeApplication || contentType == mimePlainText) {
				form := httpReq.body.form
				if (form == null)
					return csrfErr("No form data")

				csrfToken = form[tokenName]

			} else {
				httpReq.body.buf // cache the InStream so it may be re-read by the app later
				httpReq.parseMultiPartForm |Str partName, InStream in, Str:Str headers| {
					if (partName == tokenName)
						csrfToken = in.readAllStr
				}
			}
		}

		if (csrfToken == null)
			return csrfErr("Form does not contain '${tokenName}' key")

		return validateToken(csrfToken)
	}

	** Manually validates a given CSRF token. 
	** Returns 'null' if valid, or an error string if invalid.
	Obj? validateToken(Str csrfToken) {
		hash := null as Str:Obj?
		try {
			fanRaw	:= crypto.decode(csrfToken)
			fanCode	:= "using sys\n[\"${fanRaw}]"
			fanObj	:= fanCode.toBuf.readObj
			hash	 = (Str:Obj?) fanObj
		} catch (Err err)
			return csrfErr("Invalid '${tokenName}' value")

		return valFuncs.call(hash)
	}
	
	internal static Bool fromVunerableUrl(HttpRequest httpReq) {
		if (httpReq.httpMethod == "POST") {
			contentType := httpReq.headers.contentType?.noParams
			if (contentType == mimeApplication ||
				contentType == mimePlainText ||
				contentType == mimeMultipart)
				return true
		}
		return false
	}

	private Str generateToken() {
		hash := Str:Obj?[:] { ordered = true }
		genFuncs.call(hash)

		code := Buf().writeObj(hash).flip.readAllStr
		if (code.startsWith("[sys::Str:sys::Obj?]"))
			code = code[20..-1]
		code = code.replace("sys::", "")
		code = code[2..<-1]
		return crypto.encode(code)
	}

	private Str csrfErr(Str msg) {
		"Suspected CSRF attack - $msg"
	}
}

@NoDoc
const class CsrfTokenGeneration {
	private const |[Str:Obj?]|[] funcs

	private new make(|[Str:Obj?]|[] funcs) {
		this.funcs = funcs
	}

	Void call(Str:Obj? hash) {
		funcs.each { it.call(hash) }
	}
}

@NoDoc
const class CsrfTokenValidation {
	private const |[Str:Obj?]|[] funcs

	private new make(|[Str:Obj?]|[] funcs) {
		this.funcs = funcs
	}

	Obj? call(Str:Obj? hash) {
		try	funcs.each { it.call(hash) }
		catch (Err err)	return err
		return null
	}
}
