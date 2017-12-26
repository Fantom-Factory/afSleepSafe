using build

class Build : BuildPod {

	new make() {
		podName = "afSleepSafe"
		summary = "Guard against CSFR, XSS, and other web attacks"
		version = Version("0.0.1")

		meta = [
			"pod.dis"		: "Sleep Safe",
			"repo.tags"		: "web",
			"repo.public"	: "true",
			"afIoc.module"	: "afSleepSafe::SleepSafeModule"
		]

		depends = [
			"sys          1.0.70 - 1.0",
			
			// ---- Core ------------------------
			"afIoc        3.0.6  - 3.0",
			"afIocConfig  1.1.0  - 1.1",

			// ---- Web -------------------------
			"afBedSheet   1.5.8  - 1.5",

			// ---- Test ------------------------
			"afBounce     1.1.6  - 1.1",
			"concurrent   1.0.70 - 1.0",
		]

		srcDirs = [`fan/`, `fan/advanced/`, `fan/internal/`, `fan/internal/wip/`, `fan/public/`, `test/`]
		resDirs = [`doc/`]
		
		meta["afBuild.testPods"]	= "afBounce concurrent"
		meta["afBuild.testDirs"]	= "test/"
	}
}
