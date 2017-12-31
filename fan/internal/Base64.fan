
** (Service)
internal const class Base64 {
	** See http://stackoverflow.com/questions/695438/safe-characters-for-friendly-url
	** 0-9A-Za-z-._~
	private static const Str 	base64		:= "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
	
	** In normal Base64 encoding, an Int of '0' is returned as 'AAAAAAAAAAE=' which is not quite 
	** what we want!
	static Str toB64(Int int) {
		b64	:= ""

		while (int > 0) {
			rem := int % 64
			b64  = base64[rem].toChar + b64
			int  = int / 64
		}

		return b64.isEmpty ? "0" : b64
	}
	
	static Int fromB64(Str b64) {
		while (b64.startsWith("0"))
			b64 = b64[1..-1]
		total := 0
		tens := 1
		b64.eachr |chr| {
			total = total + (base64.index(chr.toChar) * tens)
			tens = tens * 64
		}
		return total
	}	
}
