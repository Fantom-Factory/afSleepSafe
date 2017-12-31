using build
using util

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
			"concurrent   1.0.70 - 1.0",
			"util         1.0.70 - 1.0",
			
			// ---- Core ------------------------
			"afIoc        3.0.6  - 3.0",
			"afIocConfig  1.1.0  - 1.1",
			"afIocEnv     1.1.0  - 1.1",
			"afConcurrent 1.0.20 - 1.1",

			// ---- Web -------------------------
			"afBedSheet   1.5.9  - 1.5",	// *****

			// ---- Test ------------------------
			"afBounce     1.1.7  - 1.1",	// *****
			"afButter     1.2.6  - 1.2",
		]

		srcDirs = [`fan/`, `fan/guards/`, `fan/guards/wip/`, `fan/internal/`, `fan/public/`, `test/`]
		resDirs = [`doc/`]
		
		meta["afBuild.testPods"]	= "afBounce afButter"
		meta["afBuild.testDirs"]	= "test/"
	}
}
