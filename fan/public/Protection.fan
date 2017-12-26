using afBedSheet::HttpRequest
using afBedSheet::HttpResponse

const mixin Protection {
	
	Str violateStr(Str what) {
		"Potential ${what} violation"
	}
	
	abstract Str? protect(HttpRequest req, HttpResponse res)
	
}
