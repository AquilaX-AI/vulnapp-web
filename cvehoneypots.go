package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// CVE-themed HTTP honeypots. Each persona is one real, recently or
// historically mass-exploited product pinned to a vulnerable version,
// listening on (or near) the port scanners actually probe for it. The
// table is driven by public exploitation reporting (CISA KEV additions,
// GreyNoise/VulnCheck/Mandiant/Greenbone trackers - see the README for
// the 2026 sources) plus the long-running "always scanned" classics.
//
// Fidelity is deliberately shallow and entirely safe: a believable
// landing page + Server banner, a few "trap" paths copied from the
// public exploit's request shape that return a plausible vulnerable
// response, and a canned `id` output if the request carries a command.
// Nothing is executed, parsed for real, or fetched. What matters is the
// log: the exact product/CVE that was targeted, the full URI, headers
// of interest, and the first bytes of the payload - second-stage
// downloader URLs included.

type cveRoute struct {
	Path   string
	Body   string
	Status int
	Hdr    string // optional single "Name: value" response header
	Trap   bool   // exploit-shaped path: tagged as an exploitation attempt
}

type cvePersona struct {
	Port        string
	Product     string
	Version     string
	CVEs        string
	Server      string
	Landing     string
	TrapHeaders []string // request headers whose presence marks an exploit
	Headers     []string // "Name: value" headers added to every response
	// RequireHeader, if set, must be present or the request gets the
	// 400 a real instance metadata service returns (e.g. Azure IMDS
	// demands "Metadata: true").
	RequireHeader string
	Routes        []cveRoute
}

func rt(path, body string) cveRoute   { return cveRoute{Path: path, Body: body} }
func trap(path, body string) cveRoute { return cveRoute{Path: path, Body: body, Trap: true} }
func trapS(path string, status int, hdr, body string) cveRoute {
	return cveRoute{Path: path, Body: body, Status: status, Hdr: hdr, Trap: true}
}

func page(title, body string) string {
	return "<!DOCTYPE html><html><head><title>" + title + "</title></head><body>" + body + "</body></html>"
}

func loginPage(title, action, version string) string {
	return page(title, `<h1>`+title+`</h1><form method="post" action="`+action+`"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form><p><small>`+version+`</small></p>`)
}

const idJSON = `{"commandResult":"uid=0(root) gid=0(root) groups=0(root)\n"}`

var cvePersonas = []cvePersona{
	// ---- Edge devices / VPN / firewalls (the most exploited category) ----
	{Port: ":4437", Product: "Citrix NetScaler Gateway", Version: "14.1-47.40", CVEs: "CVE-2023-4966,CVE-2019-19781,CVE-2026-88771",
		Server: "Citrix NetScaler", Landing: loginPage("Citrix Gateway", "/cgi/login", "NetScaler 14.1 Build 47.40"),
		Routes: []cveRoute{
			trap("/oauth/idp/.well-known/openid-configuration", `{"issuer":"https://gw.acme.local","authorization_endpoint":"https://gw.acme.local/oauth/idp/login","jwks_uri":"https://gw.acme.local/oauth/idp/certs"}`),
			trap("/vpn/../vpns/", `<html><body>Not Found</body></html>`),
			trap("/logon/LogonPoint/", loginPage("Citrix Gateway", "/cgi/login", "NetScaler 14.1")),
		}},
	{Port: ":4438", Product: "Cisco ASA", Version: "9.14.1", CVEs: "CVE-2020-3452,CVE-2024-20353",
		Server: "", Landing: loginPage("Cisco ASA - WebVPN Service", "/+webvpn+/index.html", "Cisco Adaptive Security Appliance 9.14(1)"),
		Routes: []cveRoute{trap("/+CSCOT+/", "[Cisco ASA] translation-table\nportal_inc.lua\n"), trap("/+CSCOE+/", loginPage("SSL VPN Service", "/+webvpn+/index.html", "ASA 9.14(1)"))}},
	{Port: ":4439", Product: "Cisco IOS XE Web UI", Version: "17.3.1", CVEs: "CVE-2023-20198,CVE-2023-20273",
		Server: "nginx", Landing: loginPage("Cisco IOS XE", "/webui/login", "Cisco IOS XE Software, Version 17.03.01"),
		Routes: []cveRoute{trap("/webui/logoutconfirm.html", "5a1e9c4b7d0f23e8a1"), trap("/webui/", loginPage("Cisco IOS XE", "/webui/login", "17.03.01"))}},
	{Port: ":4440", Product: "Fortinet FortiWeb", Version: "7.4.0", CVEs: "CVE-2025-64446",
		Server: "", Landing: loginPage("FortiWeb", "/login", "FortiWeb-VM 7.4.0 build 0600"),
		Routes: []cveRoute{trap("/api/v2.0/cmdb/system/admin", `{"results":{"name":"admin","accprofile":"prof_admin"}}`), trap("/cgi-bin/fwbcgi", `{"status":"ok"}`)}},
	{Port: ":4441", Product: "Check Point Quantum Gateway", Version: "R81.10", CVEs: "CVE-2024-24919",
		Server: "Check Point SVN foundation", Landing: loginPage("Check Point Mobile Access", "/Login/Login", "R81.10"),
		Routes: []cveRoute{trap("/clients/MyCRL", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n")}},
	{Port: ":4442", Product: "Ivanti Endpoint Manager Mobile (EPMM)", Version: "12.5.0.0", CVEs: "CVE-2025-4427,CVE-2025-4428,CVE-2026-1281,CVE-2026-1340",
		Server: "", Landing: loginPage("MobileIron Core / Ivanti EPMM", "/mifs/login", "Ivanti EPMM 12.5.0.0"),
		Routes: []cveRoute{trap("/mifs/rs/api/v2/", `{"results":[],"totalCount":0}`), trap("/mifs/c/", `{"error":"unauthorized"}`)}},
	{Port: ":4443", Product: "SonicWall SMA 100", Version: "10.2.1.1", CVEs: "CVE-2021-20038,CVE-2021-20016",
		Server: "SonicWALL SSL-VPN Web Server", Landing: loginPage("SonicWall Secure Mobile Access", "/cgi-bin/userLogin", "SMA 10.2.1.1-19sv"),
		Routes: []cveRoute{trap("/cgi-bin/", `<html>ok</html>`)}},
	{Port: ":4444", Product: "Sophos Firewall", Version: "SFOS 18.5.1", CVEs: "CVE-2022-1040,CVE-2020-12271",
		Server: "", Landing: loginPage("Sophos Firewall", "/webconsole/Controller", "SFOS 18.5.1 MR-1-Build326"),
		Routes: []cveRoute{trap("/webconsole/", `{"status":"ok"}`), trap("/userportal/", `{"status":"ok"}`)}},
	{Port: ":4445", Product: "F5 BIG-IP", Version: "16.1.2", CVEs: "CVE-2022-1388,CVE-2023-46747,CVE-2020-5902",
		Server: "Apache", Landing: loginPage("BIG-IP&reg; Configuration Utility", "/tmui/logmein.html", "BIG-IP 16.1.2"),
		Routes: []cveRoute{trap("/mgmt/tm/util/bash", `{"kind":"tm:util:bash:runstate","command":"run","utilCmdArgs":"-c id",`+idJSON[1:]), trap("/tmui/login.jsp", loginPage("BIG-IP", "/tmui/logmein.html", "16.1.2")), trap("/mgmt/", `{"code":401,"message":"Authorization failed"}`)}},
	{Port: ":4446", Product: "Juniper J-Web (Junos)", Version: "22.4R2", CVEs: "CVE-2023-36844,CVE-2023-36845",
		Server: "", Landing: loginPage("Juniper Web Device Manager", "/", "Junos 22.4R2.8"),
		Routes: []cveRoute{trap("/webauth_operation.php", `<html>ok</html>`), trap("/about.php", `<html>ok</html>`)}},
	{Port: ":4447", Product: "Zyxel USG FLEX", Version: "5.21", CVEs: "CVE-2022-30525,CVE-2023-28771",
		Server: "", Landing: loginPage("Zyxel USG FLEX", "/login", "V5.21(ABUS.0)"),
		Routes: []cveRoute{trap("/ztp/cgi-bin/handler", `{"status":"ok"}`)}},
	{Port: ":4448", Product: "Palo Alto PAN-OS GlobalProtect", Version: "11.0.1", CVEs: "CVE-2024-3400,CVE-2026-0310",
		Server: "PanWeb Server/ -", Landing: loginPage("GlobalProtect Portal", "/global-protect/login.esp", "PAN-OS 11.0.1"),
		Routes: []cveRoute{trap("/ssl-vpn/hipreport.esp", `<response status="success"/>`), trap("/global-protect/", loginPage("GlobalProtect Portal", "/global-protect/login.esp", "11.0.1"))}},
	{Port: ":4449", Product: "Cisco Catalyst SD-WAN Manager (vManage)", Version: "20.9.3", CVEs: "CVE-2026-20127",
		Server: "", Landing: loginPage("Cisco vManage", "/j_security_check", "20.9.3"),
		Routes: []cveRoute{trap("/dataservice/", `{"data":[]}`), trap("/j_security_check", `{"error":"auth"}`)}},

	// ---- Managed file transfer (Cl0p-style campaigns) ----
	{Port: ":4451", Product: "Progress MOVEit Transfer", Version: "2023.0.1", CVEs: "CVE-2023-34362,CVE-2023-36934",
		Server: "Microsoft-IIS/10.0", Landing: loginPage("MOVEit Transfer", "/human.aspx", "MOVEit Transfer 2023.0.1 (15.0.1)"),
		Routes: []cveRoute{trap("/human.aspx", loginPage("MOVEit Transfer", "/human.aspx", "")), trap("/guestaccess.aspx", loginPage("MOVEit Guest", "/guestaccess.aspx", ""))}},
	{Port: ":4452", Product: "Progress WS_FTP Server", Version: "8.7.3", CVEs: "CVE-2023-40044",
		Server: "Microsoft-IIS/10.0", Landing: loginPage("WS_FTP Server", "/", "WS_FTP Server 8.7.3"),
		Routes: []cveRoute{trap("/ThinClient/WTM/public/index.html", page("WS_FTP Web Transfer Module", "WTM"))}},
	{Port: ":4453", Product: "Fortra GoAnywhere MFT", Version: "7.4.1", CVEs: "CVE-2024-0204,CVE-2025-10035",
		Server: "", Landing: loginPage("GoAnywhere MFT", "/goanywhere/auth/Login.xhtml", "GoAnywhere MFT 7.4.1"),
		Routes: []cveRoute{trap("/goanywhere/", page("GoAnywhere", "Initial account setup")), trap("/license/Unlicensed.xhtml", page("License", "ok"))}},
	{Port: ":4454", Product: "Cleo Harmony / VLTrader", Version: "5.8.0.21", CVEs: "CVE-2024-50623,CVE-2024-55956",
		Server: "Cleo", Landing: loginPage("Cleo Harmony", "/Login.jsp", "5.8.0.21"),
		Routes: []cveRoute{trap("/Synchronization", `OK`), trap("/Login.jsp", loginPage("Cleo Harmony", "/Login.jsp", ""))}},
	{Port: ":4455", Product: "CrushFTP", Version: "10.8.3", CVEs: "CVE-2025-31161,CVE-2025-54309,CVE-2024-4040",
		Server: "CrushFTP HTTP Server", Landing: loginPage("CrushFTP WebInterface", "/WebInterface/function/", "CrushFTP 10.8.3"),
		Routes: []cveRoute{trap("/WebInterface/function/", `<?xml version="1.0"?><response><response_status>failure</response_status></response>`)}},
	{Port: ":5466", Product: "Wing FTP Server", Version: "7.4.3", CVEs: "CVE-2025-47812",
		Server: "Wing FTP Server(Wing FTP)", Landing: loginPage("Wing FTP Server", "/loginok.html", "Wing FTP Server 7.4.3"),
		Routes: []cveRoute{trap("/loginok.html", page("OK", "ok"))}},

	// ---- Microsoft / enterprise middleware ----
	{Port: ":4456", Product: "Microsoft SharePoint Server", Version: "16.0.10337", CVEs: "CVE-2025-53770,CVE-2025-53771,CVE-2026-50522",
		Server: "Microsoft-IIS/10.0", Landing: loginPage("Sign in - SharePoint", "/_layouts/15/Authenticate.aspx", "Microsoft SharePoint 2019"),
		Routes: []cveRoute{trap("/_layouts/15/ToolPane.aspx", page("Error", "An error occurred.")), trap("/_layouts/15/", page("SharePoint", "ok")), trap("/_vti_bin/", `<soap/>`)}},
	{Port: ":4457", Product: "Microsoft Exchange Server", Version: "15.2.858.5", CVEs: "CVE-2021-26855,CVE-2021-34473,CVE-2022-41082",
		Server: "Microsoft-IIS/10.0", Landing: loginPage("Outlook Web App", "/owa/auth.owa", "Exchange 2019 CU11"),
		Routes: []cveRoute{trap("/autodiscover/autodiscover.json", `{"Protocol":"Autodiscoverv1","Url":"https://mail.acme.local/autodiscover/autodiscover.xml"}`), trap("/ecp/", loginPage("Exchange Admin Center", "/ecp", "")), trap("/owa/auth/", loginPage("OWA", "/owa/auth.owa", ""))}},
	{Port: ":8530", Product: "Microsoft WSUS", Version: "10.0.17763", CVEs: "CVE-2025-59287",
		Server: "Microsoft-IIS/10.0", Landing: page("WSUS", "Windows Server Update Services"),
		Routes: []cveRoute{trap("/SimpleAuthWebService/", `<soap:Envelope/>`), trap("/ClientWebService/", `<soap:Envelope/>`), trap("/ReportingWebService/", `<soap:Envelope/>`)}},
	{Port: ":8040", Product: "ConnectWise ScreenConnect", Version: "23.9.7", CVEs: "CVE-2024-1709,CVE-2024-1708",
		Server: "Microsoft-HTTPAPI/2.0", Landing: loginPage("ScreenConnect", "/Login", "ScreenConnect 23.9.7.8804"),
		Routes: []cveRoute{trap("/SetupWizard.aspx", page("ScreenConnect Setup Wizard", `<form method="post"><input name="username"><input name="password"><button>Next</button></form>`))}},
	{Port: ":4458", Product: "SAP NetWeaver Visual Composer", Version: "7.50", CVEs: "CVE-2025-31324",
		Server: "SAP NetWeaver Application Server 7.50 / AS Java 7.50", Landing: page("SAP NetWeaver Application Server", "SAP NetWeaver AS Java 7.50"),
		Routes: []cveRoute{trap("/developmentserver/metadatauploader", `OK`), trap("/irj/", page("SAP Enterprise Portal", "ok"))}},
	{Port: ":4459", Product: "Oracle E-Business Suite", Version: "12.2.14", CVEs: "CVE-2025-61882,CVE-2025-61884",
		Server: "Oracle-HTTP-Server", Landing: loginPage("Oracle E-Business Suite Home Page Login", "/OA_HTML/AppsLocalLogin.jsp", "12.2.14"),
		Routes: []cveRoute{trap("/OA_HTML/configurator/UiServlet", `<html>oracle.apps.cz.servlet.UiServlet</html>`), trap("/OA_HTML/", loginPage("Oracle EBS", "/OA_HTML/AppsLocalLogin.jsp", ""))}},
	{Port: ":4460", Product: "Oracle Identity Manager", Version: "12.2.1.4", CVEs: "CVE-2025-61757",
		Server: "Oracle-HTTP-Server", Landing: loginPage("Oracle Identity Self Service", "/identity/faces/signin", "12.2.1.4.0"),
		Routes: []cveRoute{trap("/iam/governance/", `{"status":"ok"}`)}},
	{Port: ":4461", Product: "Adobe ColdFusion", Version: "2021 Update 5", CVEs: "CVE-2023-26360,CVE-2023-29300,CVE-2024-20767",
		Server: "", Landing: loginPage("ColdFusion Administrator Login", "/CFIDE/administrator/enter.cfm", "Adobe ColdFusion 2021,0,5,330468"),
		Routes: []cveRoute{trap("/CFIDE/adminapi/", `<wddxPacket version='1.0'><header/><data><string>ok</string></data></wddxPacket>`), trap("/CFIDE/administrator/", loginPage("ColdFusion Administrator", "/CFIDE/administrator/enter.cfm", ""))}},
	{Port: ":4462", Product: "N-able N-central", Version: "2025.3", CVEs: "CVE-2026-86218,CVE-2026-86206,CVE-2026-86207",
		Server: "", Landing: loginPage("N-central", "/login", "N-central 2025.3.0.12"),
		Routes: []cveRoute{trap("/dms/", `{"status":"ok"}`), trap("/api/", `{"status":"ok"}`)}},
	{Port: ":4463", Product: "Commvault Command Center", Version: "11.34", CVEs: "CVE-2025-34028,CVE-2025-57788",
		Server: "", Landing: loginPage("Command Center", "/commandcenter/login", "Commvault 11.34.20"),
		Routes: []cveRoute{trap("/commandcenter/deployWebpackage.do", `{"status":"ok"}`)}},
	{Port: ":4464", Product: "SimpleHelp Remote Support", Version: "5.5.7", CVEs: "CVE-2024-57727,CVE-2024-57728",
		Server: "SimpleHelp", Landing: loginPage("SimpleHelp", "/", "SimpleHelp 5.5.7"),
		Routes: []cveRoute{trap("/toolbox-resource/", `<serverconfig><admin user="admin" password="FAKE-hash-0001"/></serverconfig>`)}},
	{Port: ":9419", Product: "Veeam Backup & Replication", Version: "12.1.0.2131", CVEs: "CVE-2024-40711,CVE-2024-29849,CVE-2023-27532",
		Server: "Veeam Backup & Replication REST API", Landing: page("Veeam Backup REST API", "Veeam Backup &amp; Replication REST API 1.1-rev0"),
		Routes: []cveRoute{trap("/api/v1/", `{"message":"Unauthorized"}`), trap("/api/oauth2/token", `{"error":"invalid_grant"}`)}},

	// ---- Java / app servers (the long tail that never gets patched) ----
	{Port: ":7001", Product: "Oracle WebLogic Server", Version: "12.2.1.3.0", CVEs: "CVE-2020-14882,CVE-2020-14883,CVE-2023-21839,CVE-2017-10271",
		Server: "", Landing: loginPage("Oracle WebLogic Server Administration Console", "/console/j_security_check", "WebLogic Server Version: 12.2.1.3.0"),
		Routes: []cveRoute{trap("/console/css/", page("WebLogic Server Console", "Console Home")), trap("/wls-wsat/", `<soap/>`), trap("/_async/", `<soap/>`), trap("/bea_wls_internal/", page("WLS", "ok"))}},
	{Port: ":8983", Product: "Apache Solr", Version: "8.11.0", CVEs: "CVE-2019-17558,CVE-2021-44228,CVE-2019-0193",
		Server: "", Landing: page("Solr Admin", "Apache Solr 8.11.0"),
		Routes: []cveRoute{trap("/solr/", `{"responseHeader":{"status":0,"QTime":1},"status":{"core1":{"name":"core1"}}}`)}},
	{Port: ":4848", Product: "Eclipse GlassFish", Version: "4.1", CVEs: "CVE-2017-1000028,CVE-2011-0807",
		Server: "GlassFish Server Open Source Edition 4.1", Landing: page("GlassFish Console - Common Tasks", "GlassFish Server Open Source Edition 4.1"),
		Routes: []cveRoute{trap("/theme/META-INF/", "root:x:0:0:root:/root:/bin/bash\n")}},
	{Port: ":8088", Product: "Apache Hadoop YARN ResourceManager", Version: "2.7.3", CVEs: "unauth-app-submit (no CVE; widespread cryptomining)",
		Server: "", Landing: page("All Applications", "Hadoop 2.7.3 ResourceManager"),
		Routes: []cveRoute{trap("/ws/v1/cluster/apps/new-application", `{"application-id":"application_1700000000000_0001","maximum-resource-capability":{"memory":8192,"vCores":4}}`), rt("/ws/v1/cluster/info", `{"clusterInfo":{"state":"STARTED","hadoopVersion":"2.7.3"}}`)}},
	{Port: ":6066", Product: "Apache Spark Standalone REST", Version: "2.3.0", CVEs: "CVE-2018-11770",
		Server: "", Landing: `{"action":"ErrorResponse","message":"Missing protocol version.","serverSparkVersion":"2.3.0"}`,
		Routes: []cveRoute{trap("/v1/submissions/", `{"action":"CreateSubmissionResponse","success":true,"submissionId":"driver-20260101000000-0001"}`)}},
	{Port: ":8180", Product: "Apache Tomcat", Version: "9.0.30", CVEs: "CVE-2020-1938,CVE-2025-24813,CVE-2020-9484",
		Server: "", Landing: page("Apache Tomcat/9.0.30", "<h2>If you're seeing this, you've successfully installed Tomcat. Congratulations!</h2>"),
		Routes: []cveRoute{trapS("/manager/", 401, `WWW-Authenticate: Basic realm="Tomcat Manager Application"`, "401 Unauthorized"), trapS("/host-manager/", 401, `WWW-Authenticate: Basic realm="Tomcat Host Manager Application"`, "401 Unauthorized")}},
	{Port: ":8085", Product: "JBoss Application Server", Version: "6.1.0.Final", CVEs: "CVE-2017-12149,CVE-2015-7501,CVE-2017-7504",
		Server: "", Landing: page("Welcome to JBoss AS", "JBoss Application Server 6.1.0.Final"),
		Routes: []cveRoute{trap("/invoker/", "\xac\xed\x00\x05sr"), trap("/jmx-console/", page("JBoss JMX Management Console", "ok")), trap("/web-console/", page("JBoss Management", "ok"))}},
	{Port: ":8190", Product: "Atlassian Confluence", Version: "8.5.3", CVEs: "CVE-2023-22527,CVE-2023-22515,CVE-2022-26134",
		Server: "", Landing: loginPage("Log in - Confluence", "/dologin.action", "Atlassian Confluence 8.5.3"),
		Routes: []cveRoute{trap("/template/aui/text-inline.vm", "49"), trap("/setup/", page("Setup", "ok")), trap("/server-info.action", page("Server Info", "ok"))}},
	{Port: ":8929", Product: "GitLab CE", Version: "13.10.2", CVEs: "CVE-2021-22205,CVE-2023-7028",
		Server: "nginx", Landing: loginPage("Sign in - GitLab", "/users/sign_in", "GitLab Community Edition 13.10.2"),
		Routes: []cveRoute{trap("/uploads/user", `{"message":"422 Unprocessable"}`), trap("/users/password", page("Reset", "ok"))}},
	{Port: ":9443", Product: "VMware vCenter Server", Version: "6.7.0", CVEs: "CVE-2021-21972,CVE-2021-22005,CVE-2023-34048",
		Server: "", Landing: loginPage("vSphere Client", "/ui/login", "VMware vCenter Server 6.7.0"),
		Routes: []cveRoute{trap("/ui/vropspluginui/rest/services/", `{"error":"unauthorized"}`), trap("/sdk", `<soapenv:Envelope/>`)}},
	{Port: ":9251", Product: "ManageEngine ADSelfService Plus", Version: "6113", CVEs: "CVE-2021-40539,CVE-2022-28810",
		Server: "", Landing: loginPage("ADSelfService Plus", "/j_security_check", "ADSelfService Plus build 6113"),
		Routes: []cveRoute{trap("/ServletApi/", `{"status":"ok"}`), trap("/RestAPI/", `{"status":"ok"}`)}},
	{Port: ":8383", Product: "ManageEngine Desktop Central", Version: "10.0.474", CVEs: "CVE-2020-10189,CVE-2021-44515",
		Server: "", Landing: loginPage("Desktop Central", "/j_security_check", "Desktop Central 10.0.474"),
		Routes: []cveRoute{trap("/fileupload", `{"status":"ok"}`), trap("/STATE_ID/", page("ok", "ok"))}},
	{Port: ":7071", Product: "Zimbra Collaboration", Version: "8.8.15_GA_3869", CVEs: "CVE-2022-27925,CVE-2022-37042,CVE-2022-41352",
		Server: "", Landing: loginPage("Zimbra Administration", "/zimbraAdmin/", "Zimbra 8.8.15_GA_3869"),
		Routes: []cveRoute{trap("/service/extension/", `{"status":"ok"}`), trap("/zimbraAdmin/", loginPage("Zimbra Admin", "/zimbraAdmin/", ""))}},
	{Port: ":2083", Product: "cPanel", Version: "11.110.0.17", CVEs: "CVE-2023-29489",
		Server: "cpsrvd/11.110.0.17", Landing: loginPage("cPanel Login", "/login/?login_only=1", "cPanel 11.110.0.17"),
		Routes: []cveRoute{trap("/cpsess", page("cPanel", "ok")), trap("/json-api/", `{"status":0}`)}},
	{Port: ":8111", Product: "JetBrains TeamCity", Version: "2023.11.3", CVEs: "CVE-2024-27198,CVE-2024-27199,CVE-2023-42793",
		Server: "", Landing: loginPage("Log in to TeamCity", "/loginSubmit.html", "TeamCity 2023.11.3 (build 147512)"),
		Routes: []cveRoute{trap("/app/rest/", `{"version":"2023.11.3","buildNumber":"147512"}`)}},
	{Port: ":8082", Product: "Spring Cloud Gateway", Version: "3.1.0", CVEs: "CVE-2022-22947,CVE-2022-22963",
		Server: "", Landing: `{"timestamp":"2026-01-01T00:00:00.000+00:00","status":404,"error":"Not Found","path":"/"}`,
		Routes: []cveRoute{trap("/actuator/gateway/", `[]`), trap("/functionRouter", `{"timestamp":"2026-01-01","status":500,"error":"Internal Server Error"}`)}},
	{Port: ":8084", Product: "Apache Struts 2 Showcase", Version: "2.3.31", CVEs: "CVE-2017-5638,CVE-2017-9805,CVE-2018-11776",
		Server: "", Landing: page("Struts2 Showcase", "<h1>Welcome!</h1>Struts 2.3.31 Showcase"),
		Routes: []cveRoute{trap(".action", page("Struts2 Showcase", "ok")), trap("/struts2-rest-showcase/", `<orders/>`)}},
	{Port: ":8087", Product: "Apache Shiro app", Version: "1.2.4", CVEs: "CVE-2016-4437,CVE-2020-1957,CVE-2020-11989",
		Server: "", Landing: loginPage("Login", "/login", "Shiro 1.2.4"),
		Routes: []cveRoute{{Path: "/login", Body: loginPage("Login", "/login", ""), Hdr: "Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0", Trap: true}}},
	{Port: ":8095", Product: "phpMyAdmin", Version: "4.8.1", CVEs: "CVE-2018-12613,CVE-2018-19968",
		Server: "Apache/2.4.29 (Ubuntu)", Landing: loginPage("phpMyAdmin", "/index.php", "phpMyAdmin 4.8.1"),
		Routes: []cveRoute{trap("target=", page("phpMyAdmin", "ok")), trap("/setup/", page("phpMyAdmin setup", "ok"))}},
	{Port: ":8096", Product: "Laravel (debug mode)", Version: "8.4.2 / Ignition 2.5.1", CVEs: "CVE-2021-3129",
		Server: "nginx/1.18.0", Landing: page("Laravel", "Laravel v8.4.2"),
		Routes: []cveRoute{trap("/_ignition/health-check", `{"can_execute_commands":true}`), trap("/_ignition/execute-solution", `{"message":"ok"}`)}},
	{Port: ":8098", Product: "Zabbix Server", Version: "7.0.0", CVEs: "CVE-2024-42327,CVE-2022-23131",
		Server: "nginx", Landing: loginPage("Zabbix", "/index.php", "Zabbix 7.0.0"),
		Routes: []cveRoute{trap("/api_jsonrpc.php", `{"jsonrpc":"2.0","result":"7.0.0","id":1}`)}},
	{Port: ":8100", Product: "Roundcube Webmail", Version: "1.6.9", CVEs: "CVE-2025-49113,CVE-2023-43770",
		Server: "Apache/2.4.57", Landing: loginPage("Roundcube Webmail :: Welcome", "/?_task=login", "Roundcube Webmail 1.6.9"),
		Routes: []cveRoute{trap("_task=settings", page("Roundcube", "ok"))}},
	{Port: ":8101", Product: "Cacti", Version: "1.2.22", CVEs: "CVE-2022-46169",
		Server: "Apache/2.4.52 (Ubuntu)", Landing: loginPage("Login to Cacti", "/index.php", "Version 1.2.22"),
		Routes: []cveRoute{trap("/remote_agent.php", "FATAL: You are not authorized to use this service")}},
	{Port: ":8102", Product: "pfSense", Version: "2.5.2", CVEs: "CVE-2022-31814,CVE-2023-42326",
		Server: "nginx", Landing: loginPage("pfSense - Login", "/index.php", "pfSense 2.5.2-RELEASE"),
		Routes: []cveRoute{trap("/pfblockerng/", page("pfBlockerNG", "ok")), trap("/diag_command.php", loginPage("pfSense", "/index.php", ""))}},
	{Port: ":5173", Product: "Vite dev server", Version: "5.4.11", CVEs: "CVE-2025-30208,CVE-2025-31125",
		Server: "", Landing: page("Vite App", `<div id="root"></div><script type="module" src="/@vite/client"></script>`),
		Routes: []cveRoute{trap("/@fs/", "root:x:0:0:root:/root:/bin/bash\n")}},
	{Port: ":3002", Product: "Grafana", Version: "8.3.0", CVEs: "CVE-2021-43798,CVE-2021-41174",
		Server: "", Landing: loginPage("Grafana", "/login", "Grafana v8.3.0 (914fcedb72)"),
		Routes: []cveRoute{trap("/public/plugins/", "root:x:0:0:root:/root:/bin/bash\n")}},
	{Port: ":3004", Product: "Metabase", Version: "0.46.6", CVEs: "CVE-2023-38646",
		Server: "", Landing: page("Metabase", "Metabase v0.46.6"),
		Routes: []cveRoute{trap("/api/session/properties", `{"setup-token":"9aa8c1a5-0000-4fa3-0000-000000000000","version":{"tag":"v0.46.6"}}`), trap("/api/setup/validate", `{"message":"ok"}`)}},
	{Port: ":8089", Product: "Splunk Enterprise management port", Version: "9.1.2", CVEs: "CVE-2026-20253,CVE-2024-36985",
		Server: "Splunkd", Landing: `<?xml version="1.0" encoding="UTF-8"?><feed><title>splunkd</title><generator build="b6436b649711" version="9.1.2"/></feed>`,
		Routes: []cveRoute{trap("/services/", `<?xml version="1.0"?><response><messages><msg type="WARN">call not properly authenticated</msg></messages></response>`)}},
	{Port: ":8107", Product: "Apache Superset", Version: "2.0.1", CVEs: "CVE-2023-27524",
		Server: "", Landing: loginPage("Superset", "/login/", "Apache Superset 2.0.1"),
		Routes: []cveRoute{{Path: "/login", Body: loginPage("Superset", "/login/", ""), Hdr: "Set-Cookie: session=eyJfZnJlc2giOmZhbHNlfQ.FAKE.DEFAULT-SECRET_KEY; HttpOnly; Path=/", Trap: true}}},

	// ---- AI / data-science tooling (the 2025-2026 growth area) ----
	{Port: ":8265", Product: "Ray Dashboard", Version: "2.6.3", CVEs: "CVE-2023-48022 (ShadowRay)",
		Server: "", Landing: page("Ray Dashboard", "Ray 2.6.3"),
		Routes: []cveRoute{trap("/api/jobs/", `[]`), trap("/api/version", `{"version":"4","ray_version":"2.6.3"}`)}},
	{Port: ":5001", Product: "MLflow Tracking Server", Version: "2.1.1", CVEs: "CVE-2023-1177,CVE-2023-6831",
		Server: "gunicorn", Landing: page("MLflow", "MLflow 2.1.1"),
		Routes: []cveRoute{trap("/get-artifact", "root:x:0:0:root:/root:/bin/bash\n"), trap("/api/2.0/mlflow/", `{"experiments":[]}`)}},
	{Port: ":8188", Product: "ComfyUI", Version: "0.3.10", CVEs: "unauth custom-node RCE (ComfyUI-Manager)",
		Server: "", Landing: page("ComfyUI", "ComfyUI"),
		Routes: []cveRoute{trap("/object_info", `{}`), trap("/system_stats", `{"system":{"os":"posix","python_version":"3.10.12"}}`), trap("/upload/image", `{"name":"x.png"}`)}},
	{Port: ":4466", Product: "Langflow", Version: "1.2.0", CVEs: "CVE-2025-3248,CVE-2026-33017",
		Server: "uvicorn", Landing: page("Langflow", "Langflow 1.2.0"),
		Routes: []cveRoute{trap("/api/v1/validate/code", `{"imports":{"errors":[]},"function":{"errors":[]}}`), trap("/api/v1/auto_login", `{"access_token":"FAKE.TOKEN.0001","token_type":"bearer"}`)}},
	{Port: ":4467", Product: "n8n", Version: "1.65.0", CVEs: "CVE-2025-68613,CVE-2026-21858",
		Server: "", Landing: page("n8n.io - Workflow Automation", "n8n 1.65.0"),
		Routes: []cveRoute{trap("/webhook", `{"message":"Workflow was started"}`), trap("/rest/", `{"data":{}}`)}},
	{Port: ":4468", Product: "Next.js app", Version: "14.2.24", CVEs: "CVE-2025-29927,CVE-2025-55182 (React2Shell)",
		Server: "", Landing: page("Acme Portal", `<div id="__next"></div><script src="/_next/static/chunks/main.js"></script>`),
		TrapHeaders: []string{"X-Middleware-Subrequest", "Next-Action"},
		Routes:      []cveRoute{trap("/_next/", `{}`)}},
	{Port: ":4472", Product: "Orkes Conductor", Version: "3.21.0", CVEs: "CVE-2026-58138",
		Server: "", Landing: page("Conductor UI", "Orkes Conductor 3.21.0"),
		Routes: []cveRoute{trap("/api/workflow", `[]`), trap("/api/metadata/workflow", `[]`)}},
	{Port: ":8848", Product: "Alibaba Nacos", Version: "2.0.3", CVEs: "CVE-2021-29441,CVE-2023-45859",
		Server: "", Landing: page("Nacos", "Nacos 2.0.3"),
		Routes: []cveRoute{trap("/nacos/v1/auth/users", `{"totalCount":1,"pageItems":[{"username":"nacos","password":"$2a$10$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE."}]}`), trap("/nacos/v1/cs/configs", `{"pageItems":[]}`)}},
	{Port: ":9180", Product: "Apache APISIX Admin API", Version: "2.12.1", CVEs: "CVE-2022-24112,CVE-2021-45232",
		Server: "APISIX/2.12.1", Landing: `{"error_msg":"failed to check token"}`,
		Routes: []cveRoute{trap("/apisix/admin/", `{"list":[],"total":0}`), trap("/apisix/batch-requests", `[]`)}},

	// ---- CMS / commerce ----
	{Port: ":4469", Product: "Craft CMS", Version: "4.14.14", CVEs: "CVE-2025-32432,CVE-2024-56145",
		Server: "nginx", Landing: page("Craft CMS", "Craft CMS 4.14.14"),
		Routes: []cveRoute{trap("admin/actions", `{"success":false}`)}},
	{Port: ":4470", Product: "Adobe Commerce / Magento", Version: "2.4.6-p3", CVEs: "CVE-2024-34102 (CosmicSting),CVE-2022-24086",
		Server: "nginx", Landing: page("Home page", "Magento 2.4.6"),
		Routes: []cveRoute{trap("/rest/V1/", `{"message":"The consumer isn't authorized to access %resources."}`)}},
	{Port: ":4471", Product: "Apache OFBiz", Version: "18.12.9", CVEs: "CVE-2023-51467,CVE-2024-38856",
		Server: "", Landing: loginPage("OFBiz: Login", "/webtools/control/login", "Apache OFBiz 18.12.9"),
		Routes: []cveRoute{trap("/control/", `PONG`)}},

	// ---- Web servers / runtimes ----
	{Port: ":8092", Product: "Apache HTTP Server", Version: "2.4.49", CVEs: "CVE-2021-41773,CVE-2021-42013",
		Server: "Apache/2.4.49 (Unix)", Landing: page("It works!", "<h1>It works!</h1>"),
		Routes: []cveRoute{trap("%2e/", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"), trap(".%2e/", "root:x:0:0:root:/root:/bin/bash\n")}},
	{Port: ":8094", Product: "Apache + PHP-CGI (Windows)", Version: "2.4.58 / PHP 8.1.26", CVEs: "CVE-2024-4577",
		Server: "Apache/2.4.58 (Win64) PHP/8.1.26", Landing: page("XAMPP", "XAMPP for Windows"),
		Routes: []cveRoute{trap("php-cgi", `<?php phpinfo(); ?>`), trap("%ad", `PHP Version 8.1.26`)}},
	{Port: ":3128", Product: "Squid Proxy", Version: "3.5.20", CVEs: "open-proxy / CVE-2019-18678",
		Server: "squid/3.5.20", Landing: page("ERROR: The requested URL could not be retrieved", "Squid/3.5.20"),
		Routes: []cveRoute{trap("/squid-internal-mgr/", "Squid Object Cache: Version 3.5.20\n")}},

	// ---- Routers / IoT (Mirai-family botnets live here) ----
	{Port: ":7547", Product: "TR-069 CWMP (home router)", Version: "RomPager 4.07", CVEs: "CVE-2014-9222 (Misfortune Cookie),CVE-2016-10372",
		Server: "RomPager/4.07 UPnP/1.0", Landing: page("401", "Unauthorized"),
		Routes: []cveRoute{trap("/UD/", `<?xml version="1.0"?><s:Envelope/>`), trap("/tr064/", `<root/>`)}},
	{Port: ":52869", Product: "Realtek SDK miniigd UPnP", Version: "1.0", CVEs: "CVE-2014-8361",
		Server: "Linux/2.6 UPnP/1.0 MiniUPnPd/1.0", Landing: page("UPnP", "ok"),
		Routes: []cveRoute{trap("/picsdesc.xml", `<?xml version="1.0"?><root><device><friendlyName>WAN Device</friendlyName></device></root>`), trap("/wanipcn.xml", `<scpd/>`)}},
	{Port: ":8083", Product: "GPON home router", Version: "H640", CVEs: "CVE-2018-10561,CVE-2018-10562",
		Server: "GoAhead-Webs", Landing: loginPage("GPON Home Gateway", "/GponForm/LoginForm", "H640 V1.0"),
		Routes: []cveRoute{trap("/GponForm/diag_Form", `<html>ok</html>`)}},
	{Port: ":8844", Product: "DrayTek Vigor", Version: "2960 1.5.1", CVEs: "CVE-2020-8515,CVE-2024-12987",
		Server: "DWS", Landing: loginPage("Vigor Login Page", "/cgi-bin/wlogin.cgi", "Vigor2960"),
		Routes: []cveRoute{trap("/cgi-bin/mainfunction.cgi", `<html>ok</html>`)}},
}

// exploitCmdPattern spots a shell command smuggled into a request - the
// first thing nearly every mass-exploitation script sends to check for
// success (`id`, `whoami`, `uname`).
var exploitCmdPattern = regexp.MustCompile("(?i)(?:[;|&`$(=+>]|%3b|%7c|%26|%60|%24)\\s*(id|whoami|uname(?:\\s+-a)?)(?:\\s|$|[;|&)`\"'<]|%0a|%20|%26|%3b)")

func init() {
	for _, p := range allHTTPPersonas() {
		portAttackCategory[p.Port] = p.Product + " Exploitation Attempt (" + p.CVEs + ")"
		servicePortName[p.Port] = p.Product + " " + p.Version
	}
}

func allHTTPPersonas() []cvePersona {
	return append(append([]cvePersona{}, cvePersonas...), azurePersonas...)
}

func startCVEHoneypots() {
	for _, p := range allHTTPPersonas() {
		startCVEHTTPService(p)
	}
	startCVETCPServices()
	startCVEUDPServices()
}

func startCVEHTTPService(p cvePersona) {
	ln, err := net.Listen("tcp", p.Port)
	if err != nil {
		log.Printf("CVE honeypot %s (%s) not started: %v", p.Port, p.Product, err)
		return
	}
	dest := ln.Addr().String()
	category := attackCategoryForAddr(p.Port)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		ua := r.Header.Get("User-Agent")
		rememberConnMeta(r.RemoteAddr, dest, "http", ua)

		route, matched := p.match(r)
		if !matched {
			for _, hn := range p.TrapHeaders {
				if r.Header.Get(hn) != "" {
					route, matched = cveRoute{Body: `{}`, Trap: true}, true
				}
			}
		}

		if matched && route.Trap {
			payload := ""
			if exploitCmdPattern.MatchString(r.URL.RequestURI()+" "+string(body)) || exploitPayloadPattern.MatchString(r.URL.RequestURI()+" "+string(body)) {
				payload = " rce_payload=true"
			}
			log.Printf("%s %s %s [T1190 Exploit Public-Facing Application | %s Exploitation Attempt (%s)] dest=%s proto=http ua=%q ct=%q body=%q%s",
				r.RemoteAddr, r.Method, r.URL.RequestURI(), p.Product, p.CVEs, dest, ua, r.Header.Get("Content-Type"), truncate(string(body), 400), payload)
		} else {
			log.Printf("%s %s %s [T1133 External Remote Services | %s] dest=%s proto=http ua=%q",
				r.RemoteAddr, r.Method, r.URL.RequestURI(), category, dest, ua)
		}

		if p.Server != "" {
			w.Header().Set("Server", p.Server)
		}
		for _, h := range p.Headers {
			if name, val, ok := strings.Cut(h, ": "); ok {
				w.Header().Set(name, val)
			}
		}
		if p.RequireHeader != "" && r.Header.Get(p.RequireHeader) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"Bad request. Required metadata header not specified"}`)
			return
		}
		// Bait: a smuggled shell command gets a believable answer so the
		// attacker moves on to the interesting second stage.
		if matched && route.Trap {
			if m := exploitCmdPattern.FindStringSubmatch(r.URL.RequestURI() + " " + string(body)); m != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				fmt.Fprint(w, rootShellOutput(m[1]))
				return
			}
		}
		out, status := p.Landing, 200
		if matched {
			out = route.Body
			if route.Status != 0 {
				status = route.Status
			}
			if name, val, ok := strings.Cut(route.Hdr, ": "); ok {
				w.Header().Set(name, val)
			}
		}
		switch {
		case strings.HasPrefix(out, "{") || strings.HasPrefix(out, "["):
			w.Header().Set("Content-Type", "application/json")
		case strings.HasPrefix(out, "<?xml") || strings.HasPrefix(out, "<soap"):
			w.Header().Set("Content-Type", "text/xml")
		case strings.HasPrefix(out, "<"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, out)
	})
	go func() {
		if err := (&http.Server{Handler: h}).Serve(ln); err != nil {
			log.Printf("CVE honeypot %s stopped: %v", p.Port, err)
		}
	}()
}

// match finds the first route hit by the request. Trap routes match
// anywhere in the (lower-cased) raw request URI so double-encoded or
// path-parameter bypass tricks (`..;/`, `%252e`) still land on them;
// plain routes match as a path prefix.
func (p cvePersona) match(r *http.Request) (cveRoute, bool) {
	uri := strings.ToLower(r.URL.RequestURI())
	for _, rt := range p.Routes {
		path := strings.ToLower(rt.Path)
		if rt.Trap && strings.Contains(uri, path) {
			return rt, true
		}
		if !rt.Trap && strings.HasPrefix(strings.ToLower(r.URL.Path), path) {
			return rt, true
		}
	}
	return cveRoute{}, false
}

// rootShellOutput is fakeShellOutput's answer as a root-privileged
// process - what a successful pre-auth RCE on most of these products
// would look like.
func rootShellOutput(cmd string) string {
	switch first, _, _ := strings.Cut(strings.ToLower(cmd), " "); first {
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	case "whoami":
		return "root\n"
	}
	return strings.ReplaceAll(fakeShellOutput(cmd), "www-data", "root")
}
