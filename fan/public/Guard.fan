using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

const mixin Guard {
	
	Str violateStr(Str what) {
		"Potential ${what} violation"
	}
	
	abstract Str? guard(HttpRequest req, HttpResponse res)
	
}
