#Sleep Safe v0.0.0
---

[![Written in: Fantom](http://img.shields.io/badge/written%20in-Fantom-lightgray.svg)](http://fantom-lang.org/)
[![pod: v0.0.0](http://img.shields.io/badge/pod-v0.0.0-yellow.svg)](http://www.fantomfactory.org/pods/afSleepSafe)
![Licence: ISC Licence](http://img.shields.io/badge/licence-ISC Licence-blue.svg)

## Overview

Guards your BedSheet web app against CSFR, XSS, and other attacks, letting you Sleep Safe at night!

For the most part, Sleep Safe is completely unobtrusive. Simply reference `afSleepSafe` as a dependecny in your project's `build.fan` and let the sensible defaults monitor your HTTP requests and set protective HTTP response headers.

Note that other Alien-Factory libraries integrate seemlessly with Sleep Safe:

- [Duvet](http://eggbox.fantomfactory.org/pods/afDuvet) - When injecting scripts and stylesheets, Duvet will automatically adjust the Content-Security-Policy to include a hash of the added content.
- [FormBean](http://eggbox.fantomfactory.org/pods/afFormBean) - When rendering forms, FormBean will automatically render any CSRF token as hidden inputs.

## Install

Install `Sleep Safe` with the Fantom Pod Manager ( [FPM](http://eggbox.fantomfactory.org/pods/afFpm) ):

    C:\> fpm install afSleepSafe

Or install `Sleep Safe` with [fanr](http://fantom.org/doc/docFanr/Tool.html#install):

    C:\> fanr install -r http://eggbox.fantomfactory.org/fanr/ afSleepSafe

To use in a [Fantom](http://fantom-lang.org/) project, add a dependency to `build.fan`:

    depends = ["sys 1.0", ..., "afSleepSafe 0.0"]

## Documentation

Full API & fandocs are available on the [Eggbox](http://eggbox.fantomfactory.org/pods/afSleepSafe/) - the Fantom Pod Repository.

## Sleep Safe Guards

Sleep Safe is BedSheet middleware that inspects HTTP requests as they come in and returns a `403 Forbidden` should an attack be suspected.

Request inspection is done by Guard classes, and include:

```
table:
Class                   Guards Against                            Notes
----------------------  ----------------------------------------  ------------
`CspGuard`              Cross Site Scripting (XSS)                Sets a 'Content-Security-Policy' HTTP response header that tells browsers to restrict where content can be loaded from.
`ContentTypeGuard`      Content Sniffing                          Sets a 'X-Content-Type-Options' HTTP response header that tells browsers to trust the 'Content-Type' header
`CsrfTokenGuard`        Cross Site Forgery Requests (CSRF)        Enforces an customisable Encrypted Token Pattern strategy
`FrameOptionsGuard`     Clickjacking                              Sets an 'X-Frame-Options' HTTP header that tells browsers not to embed the page in a frame
`ReferrerPolicyGuard`   Private / internal URL leaking            Sets a 'Referrer-Policy' HTTP response header that tells browsers how and when to transmit the HTTP Referer (sic) header
`SameOriginGuard`       Cross Site Forgery Requests (CSRF)        Checks the 'Referer' or 'Origin' HTTP header matches the 'Host'
`SessionHijackGuard`    Session Hijacking                         Caches browser user-agent parameters and checks them on each request, dropping the session if they change.
`StrictTransportGuard`  Protocol Downgrades and Cookie Hijacking  Sets a 'Strict-Transport-Security' HTTP header that tells browsers to use HTTPS
`XssProtectionGuard`    Cross Site Scripting (XSS)                Sets an 'X-XSS-Protection' HTTP header that tells browsers enable XSS filtering
```

- [CspGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/CspGuard) - Guards against Cross Site Scripting (XSS) by setting an `Content-Security-Policy` HTTP response header that tells browsers to restrict where content can be loaded from.
- [CsrfTokenGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/CsrfTokenGuard) - Guards against CSRF attacks by enforcing an customisable Encrypted Token Pattern strategy.
- [FrameOptionsGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/FrameOptionsGuard) - Guards against clickjacking by setting an `X-Frame-Options` HTTP response header that tells browsers not to embed the page in a frame.
- [ReferrerPolicyGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/ReferrerPolicyGuard) - Guards against internal URL leakage by setting a `Referrer-Policy` HTTP response header that tells browsers how and when to transmit the HTTP Referer (sic) header.
- [SameOriginGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/SameOriginGuard) - Guards against CSRF attacks by checking that the `Referer` or `Origin` HTTP header matches the `Host`.
- [SessionHijackGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/SessionHijackGuard) - Guards against Session hijacking by caching browser user-agent parameters and checking them on each request.
- [StrictTransportGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/StrictTransportGuard) - Guards against protocol downgrade attacks and Cookie hijacking by setting a `Strict-Transport-Security` HTTP response header that tells browsers to use HTTPS.
- [ContentTypeGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/ContentTypeGuard) - Guards against dodgy Content-Type sniffing by setting a `X-Content-Type-Options` HTTP response header that tells browsers to trust the `Content-Type` header.
- [XssProtectionGuard](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/XssProtectionGuard) - Guards against Cross Site Scripting (XSS) by setting an `X-XSS-Protection` HTTP response header that tells browsers enable XSS filtering.

See the individual class documentation for more details.

## IoC Configuration

When a Guard rejects a HTTP request, it processes a standard BedSheet `HttpStatus` object with a `403 - Forbidden` status code. This is then handled by BedSheet in the usual manner, for you to override - see [HTTP Status Processing](http://eggbox.fantomfactory.org/pods/afBedSheet/doc/#httpStatusProcessing).

Use IoC Config to change the status code:

```
@Contribute { serviceType=ApplicationDefaults# }
Void contributeAppDefaults(Configuration config) {
    config["afSleepSafe.rejectedStatusCode"] = 400
}
```

or as [SleepSafeMiddleware](http://eggbox.fantomfactory.org/pods/afSleepSafe/api/SleepSafeMiddleware) is a service, you can override it and the `rejectSuspectedAttack()` method.

## References

Use [https://observatory.mozilla.org/](https://observatory.mozilla.org/) to probe your site's HTTP response headers and give information on how best to configure them.

Sleep Safe was inspired by Ruby's [Rack Protection](https://github.com/sinatra/sinatra/tree/master/rack-protection) library.
