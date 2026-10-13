package main

// Azure-themed honeypots: look-alikes of the endpoints and network
// services that Azure customers most often leave exposed - storage
// emulators and anonymous blob listings, Kudu/SCM, managed-identity and
// instance-metadata endpoints, Functions admin APIs, Key Vault and
// Container Registry with public access, the OMIGOD agent that Azure
// silently installs on Linux VMs, Service Fabric, ADFS, RD Gateway, and
// the identity/data-plane ports (LDAPS, Kerberos, Cosmos, Event Hubs)
// that show up on internet scans of Azure address space. Same engine
// and safety model as cvehoneypots.go: banner fidelity, trap paths,
// canned bait, full logging - nothing real behind any of it. All tokens,
// keys, subscription IDs and tenant IDs are fake.

const (
	azFakeJWT    = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.FAKE-PAYLOAD.DO-NOT-USE"
	azSub        = "00000000-0000-0000-0000-00000000f4ce"
	azTenant     = "11111111-1111-1111-1111-1111deadbeef"
	azHTTPAPI    = "Microsoft-HTTPAPI/2.0"
	azBlobServer = "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0"
)

var azMSHeaders = []string{"x-ms-request-id: 0b6f3a4e-901e-0043-6d5c-fe1a1d000000", "x-ms-version: 2021-08-06"}

var azurePersonas = []cvePersona{
	// ---- Storage ----
	{Port: ":10100", Product: "Azure Blob Storage (public container)", Version: "2021-08-06", CVEs: "anonymous container listing / leaked SAS token",
		Server: azBlobServer, Headers: azMSHeaders, Landing: "",
		Routes: []cveRoute{
			trap("comp=list", `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://acmeprod.blob.core.windows.net/" ContainerName="backups"><Blobs><Blob><Name>db-backup-2026-10-01.bak</Name><Properties><Content-Length>734003200</Content-Length></Properties></Blob><Blob><Name>appsettings.Production.json</Name></Blob><Blob><Name>terraform.tfstate</Name></Blob><Blob><Name>id_rsa</Name></Blob></Blobs></EnumerationResults>`),
			trap("sig=", `{"note":"SAS token accepted"}`),
			trapS("/backups/", 200, "", `FAKE-BLOB-CONTENT`),
			{Path: "/", Status: 400, Body: `<?xml version="1.0" encoding="utf-8"?><Error><Code>InvalidUri</Code><Message>The requested URI does not represent any resource on the server.</Message></Error>`},
		}},
	{Port: ":10001", Product: "Azure Queue Storage / Azurite", Version: "3.31.0", CVEs: "storage emulator exposed with well-known dev key",
		Server: azHTTPAPI, Headers: azMSHeaders, Landing: "",
		Routes: []cveRoute{trap("comp=list", `<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="http://127.0.0.1:10001/devstoreaccount1"><Queues><Queue><Name>orders</Name></Queue><Queue><Name>payments-dlq</Name></Queue></Queues></EnumerationResults>`),
			{Path: "/", Status: 400, Body: `<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthenticationFailed</Code></Error>`}}},
	{Port: ":10002", Product: "Azure Table Storage / Azurite", Version: "3.31.0", CVEs: "storage emulator exposed with well-known dev key",
		Server: azHTTPAPI, Headers: azMSHeaders, Landing: `{"odata.error":{"code":"AuthenticationFailed"}}`,
		Routes: []cveRoute{trap("/Tables", `{"odata.metadata":"http://127.0.0.1:10002/devstoreaccount1/$metadata#Tables","value":[{"TableName":"Users"},{"TableName":"AuditLog"},{"TableName":"ApiKeys"}]}`)}},
	{Port: ":8900", Product: "Azure Cosmos DB Emulator", Version: "2.14.x", CVEs: "emulator reachable with the documented public master key",
		Server: azHTTPAPI, Headers: []string{"x-ms-version: 2018-12-31"},
		Landing: `{"_self":"","id":"localhost","_rid":"localhost","media":"//media/","addresses":"//addresses/","_dbs":"//dbs/","writableLocations":[{"name":"South Central US","databaseAccountEndpoint":"https://localhost:8900/"}],"userReplicationPolicy":{"asyncReplication":false,"minReplicaSetSize":1,"maxReplicasetSize":4}}`,
		Routes:  []cveRoute{trap("/_explorer/", page("Azure Cosmos DB Emulator", "Data Explorer - key C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==")), trap("/dbs", `{"Databases":[{"id":"orders"},{"id":"customers"}],"_count":2}`)}},

	// ---- App Service / Functions / identity endpoints ----
	{Port: ":8444", Product: "Azure App Service Kudu (SCM)", Version: "1.0.0", CVEs: "exposed Kudu: /api/settings, /api/command, /api/vfs",
		Server: "Microsoft-IIS/10.0", Headers: []string{"X-Powered-By: ASP.NET", "X-AspNet-Version: 4.0.30319"},
		Landing: page("Kudu Services", "<h1>Kudu</h1><ul><li><a href=\"/Env.cshtml\">Environment</a></li><li><a href=\"/DebugConsole\">Debug console</a></li><li><a href=\"/api/deployments\">Deployments</a></li></ul>"),
		Routes: []cveRoute{
			trap("/api/settings", `{"WEBSITE_SITE_NAME":"acme-webapp","WEBSITE_AUTH_ENCRYPTION_KEY":"FAKE4B1D0E6C","APPSETTING_SqlConnection":"Server=tcp:acme-sql.database.windows.net,1433;User ID=sqladmin;Password=Pr0d-DB-FAKE!;","AZURE_STORAGE_KEY":"FAKEFAKEFAKE/FAKE=="}`),
			trap("/api/command", `{"Output":"","Error":"","ExitCode":0}`),
			trap("/api/vfs/", `[{"name":"web.config","size":1432,"mime":"text/xml"},{"name":"appsettings.json","size":2210,"mime":"application/json"}]`),
			trap("/env.cshtml", page("Environment", "<pre>COMPUTERNAME=RD0003FF1A2B3C\nWEBSITE_SITE_NAME=acme-webapp\nMSI_ENDPOINT=http://127.0.0.1:8310/msi/token</pre>")),
			trap("/debugconsole", page("Kudu Debug Console", "<pre>D:\\home&gt;</pre>")),
		}},
	{Port: ":8445", Product: "ASP.NET on Azure App Service (debug exposure)", Version: "4.8", CVEs: "Easy Auth token leak, trace.axd/elmah.axd exposure",
		Server: "Microsoft-IIS/10.0", Headers: []string{"X-Powered-By: ASP.NET", "X-AspNet-Version: 4.0.30319"},
		Landing: page("Acme Orders", "Acme Orders portal"),
		Routes: []cveRoute{
			trap("/.auth/me", `[{"access_token":"`+azFakeJWT+`","expires_on":"2026-10-14T00:00:00.0000000Z","provider_name":"aad","user_id":"admin@acme.onmicrosoft.com","user_claims":[{"typ":"tid","val":"`+azTenant+`"}]}]`),
			trap("/trace.axd", page("Application Trace", "<pre>/Orders/Edit?id=1 POST connectionString=Server=tcp:acme-sql.database.windows.net;Password=Pr0d-DB-FAKE!</pre>")),
			trap("/elmah.axd", page("Error Log for acme-webapp", "<pre>System.Data.SqlClient.SqlException: Login failed for user 'sqladmin'</pre>")),
			trap("/web.config", `<configuration><connectionStrings><add name="Db" connectionString="Server=tcp:acme-sql.database.windows.net;User ID=sqladmin;Password=Pr0d-DB-FAKE!"/></connectionStrings></configuration>`),
		}},
	{Port: ":7073", Product: "Azure Functions host", Version: "4.34.1", CVEs: "exposed /admin APIs + leaked master/function keys",
		Server: "Kestrel", Landing: page("Your Functions 4.0 app is up and running", "Your Functions 4.0 app is up and running."),
		Routes: []cveRoute{
			trap("/admin/host/status", `{"id":"acme-func","state":"Running","version":"4.34.1.22669","versionDetails":"4.34.1+3a1c"}`),
			trap("/admin/host/keys", `{"keys":[{"name":"_master","value":"FAKEmasterKEY0000000000000000000000000000==","encrypted":false}],"links":[]}`),
			trap("/admin/functions", `[{"name":"ProcessOrder","invoke_url_template":"http://localhost:7073/api/processorder"}]`),
			trap("/runtime/webhooks/", `{"error":"unauthorized"}`),
		}},
	{Port: ":8310", Product: "Azure App Service managed-identity endpoint (MSI)", Version: "2019-08-01", CVEs: "SSRF -> managed identity token theft",
		Server: "", RequireHeader: "X-IDENTITY-HEADER", Landing: `{"error":"not found"}`,
		Routes: []cveRoute{trap("/msi/token", `{"access_token":"`+azFakeJWT+`","expires_on":"1792000000","resource":"https://management.azure.com/","token_type":"Bearer","client_id":"`+azSub+`"}`)}},
	{Port: ":8312", Product: "Azure Instance Metadata Service (IMDS)", Version: "2023-07-01", CVEs: "SSRF -> VM metadata & managed-identity token theft",
		Server: "Microsoft-IIS/10.0", RequireHeader: "Metadata", Landing: `{"error":"Not found"}`,
		Routes: []cveRoute{
			trap("/metadata/identity/oauth2/token", `{"access_token":"`+azFakeJWT+`","client_id":"`+azSub+`","expires_in":"86399","expires_on":"1792000000","resource":"https://management.azure.com/","token_type":"Bearer"}`),
			trap("/metadata/instance", `{"compute":{"azEnvironment":"AzurePublicCloud","location":"westeurope","name":"acme-web01","osType":"Linux","resourceGroupName":"acme-prod-rg","subscriptionId":"`+azSub+`","vmSize":"Standard_D4s_v3","osProfile":{"adminUsername":"azureuser","computerName":"acme-web01"},"tags":"env:prod"},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.4.23","publicIpAddress":"203.0.113.10"}]}}]}}`),
		}},
	{Port: ":32526", Product: "Azure VM Guest Agent (WireServer / HostGAPlugin)", Version: "2015-04-05", CVEs: "extension protectedSettings & goal-state disclosure",
		Server: azHTTPAPI, Landing: `<?xml version="1.0" encoding="utf-8"?><Versions><Preferred><Version>2015-04-05</Version></Preferred><Supported><Version>2015-04-05</Version></Supported></Versions>`,
		Routes: []cveRoute{
			trap("/vmsettings", `{"hostGAPluginVersion":"1.0.8.133","extensionGoalStates":[{"name":"Microsoft.Azure.Extensions.CustomScript","settings":[{"protectedSettings":"FAKE-ENCRYPTED-BLOB","publicSettings":"{\"commandToExecute\":\"bash setup.sh\"}"}]}]}`),
			trap("/machine/", `<?xml version="1.0"?><GoalState><Incarnation>1</Incarnation><Container><ContainerId>fake-container</ContainerId></Container></GoalState>`),
			trap("/extensionartifact", `FAKE-EXTENSION-ZIP`),
		}},
	{Port: ":5986", Product: "Microsoft OMI (OMIGOD)", Version: "1.6.8-1", CVEs: "CVE-2021-38647,CVE-2021-38648,CVE-2021-38645,CVE-2021-38649",
		Server: "", Landing: `<html><body>401 Unauthorized</body></html>`,
		Routes: []cveRoute{trap("/wsman", `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><p:ExecuteShellCommand_OUTPUT><p:StdOut></p:StdOut><p:ReturnCode>0</p:ReturnCode></p:ExecuteShellCommand_OUTPUT></s:Body></s:Envelope>`)}},
	{Port: ":1270", Product: "Microsoft OMI (OMIGOD) - Azure Monitor/OMS agent", Version: "1.6.8-1", CVEs: "CVE-2021-38647,CVE-2021-38648",
		Server: "", Landing: `<html><body>401 Unauthorized</body></html>`,
		Routes: []cveRoute{trap("/wsman", `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><p:ExecuteShellCommand_OUTPUT><p:StdOut></p:StdOut><p:ReturnCode>0</p:ReturnCode></p:ExecuteShellCommand_OUTPUT></s:Body></s:Envelope>`)}},

	// ---- Data plane / DevOps ----
	{Port: ":8202", Product: "Azure Key Vault (public network access)", Version: "7.4", CVEs: "vault reachable from the internet; weak/absent access policy",
		Server: "Kestrel", Headers: []string{"x-ms-keyvault-region: westeurope", "x-ms-keyvault-service-version: 1.9.1128.1", "x-ms-request-id: 4f1c0d52-0000-0000-0000-000000000000"},
		Landing: `{"error":{"code":"Unauthorized","message":"AKV10000: Request is missing a Bearer or PoP token."}}`,
		Routes: []cveRoute{
			trap("/secrets", `{"value":[{"id":"https://acme-kv.vault.azure.net/secrets/db-password","attributes":{"enabled":true}},{"id":"https://acme-kv.vault.azure.net/secrets/storage-key","attributes":{"enabled":true}}],"nextLink":null}`),
			trap("/keys", `{"value":[{"kid":"https://acme-kv.vault.azure.net/keys/signing-key"}]}`),
			trap("/certificates", `{"value":[]}`),
		}},
	{Port: ":5002", Product: "Azure Container Registry (anonymous pull)", Version: "2.0", CVEs: "anonymous pull / admin user enabled",
		Server: azHTTPAPI, Headers: []string{"Docker-Distribution-Api-Version: registry/2.0", "X-Content-Type-Options: nosniff"},
		Landing: `{}`,
		Routes: []cveRoute{
			trap("/v2/_catalog", `{"repositories":["acme/orders-api","acme/auth-svc","acme/internal-tools"]}`),
			trap("/v2/", `{}`),
		}},
	{Port: ":8093", Product: "Azure DevOps Server (on-prem)", Version: "2020.1", CVEs: "anonymous project access / leaked PATs in repos",
		Server: "Microsoft-IIS/10.0", Headers: []string{"X-TFS-ProcessId: 0b1c2d3e-0000-0000-0000-000000000000", "X-VSS-E2EID: 00000000-0000-0000-0000-000000000000"},
		Landing: loginPage("Azure DevOps Server", "/tfs/", "Azure DevOps Server 2020 Update 1"),
		Routes:  []cveRoute{trap("/tfs/", `{"count":2,"value":[{"name":"orders","visibility":"private"},{"name":"infra","visibility":"private"}]}`), trap("/_apis/connectionData", `{"instanceId":"00000000-0000-0000-0000-000000000000","deploymentType":"onPremises"}`)}},
	{Port: ":19080", Product: "Azure Service Fabric Explorer", Version: "9.1.1583.9590", CVEs: "unauthenticated cluster management API",
		Server: azHTTPAPI, Landing: page("Service Fabric Explorer", "Service Fabric Explorer"),
		Routes: []cveRoute{
			trap("/$/GetClusterManifest", `{"Manifest":"<ClusterManifest Name=\"acme-sf\" Version=\"1.0\"/>"}`),
			trap("/$/GetClusterHealth", `{"AggregatedHealthState":"Ok","NodeHealthStates":[]}`),
			trap("/Applications", `{"ContinuationToken":"","Items":[]}`),
		}},
	{Port: ":8442", Product: "Azure HDInsight Ambari", Version: "2.7.5", CVEs: "default admin/admin credentials",
		Server: "", Landing: page("Ambari", "Apache Ambari 2.7.5"),
		Routes: []cveRoute{trap("/api/v1/clusters", `{"items":[{"Clusters":{"cluster_name":"acme-hdi","version":"HDP-3.1"}}]}`), trap("/api/v1/users", `{"items":[{"Users":{"user_name":"admin"}}]}`)}},
	{Port: ":8998", Product: "Apache Livy (HDInsight Spark)", Version: "0.7.0", CVEs: "unauthenticated session creation -> RCE on the cluster",
		Server: "Jetty(9.3.24.v20180605)", Landing: `{"msg":"Livy"}`,
		Routes: []cveRoute{trap("/sessions", `{"from":0,"total":0,"sessions":[]}`), trap("/batches", `{"from":0,"total":0,"sessions":[]}`)}},
	{Port: ":3500", Product: "Dapr sidecar API (AKS / Container Apps)", Version: "1.13.2", CVEs: "unauthenticated sidecar API (no app-api-token)",
		Server: "", Landing: ``,
		Routes: []cveRoute{
			trap("/v1.0/metadata", `{"id":"orders-api","runtimeVersion":"1.13.2","registeredComponents":[{"name":"statestore","type":"state.redis"},{"name":"secretstore","type":"secretstores.azure.keyvault"}]}`),
			trap("/v1.0/secrets/", `{"db-password":"Pr0d-DB-FAKE!"}`),
			trap("/v1.0/state/", `{}`),
			trap("/v1.0/invoke/", `{}`),
		}},

	// ---- Identity / remote access ----
	{Port: ":4481", Product: "Active Directory Federation Services (ADFS)", Version: "10.0.17763", CVEs: "metadata disclosure, user enumeration, password spray, Golden SAML",
		Server: azHTTPAPI, Landing: loginPage("Sign In", "/adfs/ls/", "Active Directory Federation Services"),
		Routes: []cveRoute{
			trap("/federationmetadata/2007-06/federationmetadata.xml", `<?xml version="1.0"?><EntityDescriptor entityID="http://sts.acme.local/adfs/services/trust"><RoleDescriptor/></EntityDescriptor>`),
			trap("/adfs/services/trust/mex", `<?xml version="1.0"?><definitions name="ADFS"/>`),
			trap("/adfs/ls/", loginPage("Sign In", "/adfs/ls/", "")),
			trap("/idpinitiatedsignon", loginPage("Sign In", "/adfs/ls/", "")),
		}},
	{Port: ":4482", Product: "RD Web Access / RD Gateway", Version: "10.0.17763", CVEs: "CVE-2020-0609,CVE-2020-0610,CVE-2019-0708 (adjacent RDP)",
		Server: "Microsoft-IIS/10.0", Landing: loginPage("RD Web Access", "/RDWeb/Pages/en-US/login.aspx", "Work Resources"),
		Routes: []cveRoute{trap("/rdweb/", loginPage("RD Web Access", "/RDWeb/Pages/en-US/login.aspx", "")), trap("/rpc/rpcproxy.dll", ``)}},

	// ---- Front-door / gateway fingerprints ----
	{Port: ":4483", Product: "Azure Application Gateway (WAF detection mode)", Version: "v2", CVEs: "WAF in detection-only mode / backend origin bypass",
		Server: "Microsoft-Azure-Application-Gateway/v2", Landing: page("502 Bad Gateway", "<center><h1>502 Bad Gateway</h1></center><hr><center>Microsoft-Azure-Application-Gateway/v2</center>"),
		Routes: []cveRoute{trap("/.env", `502`)}},
	{Port: ":4484", Product: "Azure Front Door", Version: "classic", CVEs: "origin exposed directly, bypassing Front Door WAF",
		Server: "", Headers: []string{"X-Azure-Ref: 0aBcDeFgHiJkLmNoPqRsTuVwXyZ0000000000", "X-Cache: CONFIG_NOCACHE"},
		Landing: page("Our services aren't available right now", "<h1>Our services aren't available right now</h1><p>We're working to restore all services as soon as possible.</p>"),
		Routes:  []cveRoute{trap("/.git/", `403`)}},
}

var azureTCPDecoys = []tcpDecoy{
	{Port: ":636", Product: "Entra Domain Services secure LDAP (LDAPS)", CVEs: "LDAPS exposed to the internet", Category: "Directory Service Brute-Force / Enumeration Attempt"},
	{Port: ":389", Product: "LDAP (Entra Domain Services / AD DS)", CVEs: "anonymous bind / enumeration", Category: "Directory Service Brute-Force / Enumeration Attempt"},
	{Port: ":88", Product: "Kerberos KDC", CVEs: "AS-REP roasting / Kerberoasting / user enumeration", Category: "Kerberos Attack Attempt"},
	{Port: ":3268", Product: "AD Global Catalog", CVEs: "directory enumeration", Category: "Directory Service Brute-Force / Enumeration Attempt"},
	{Port: ":135", Product: "MS-RPC endpoint mapper", CVEs: "RPC enumeration (CVE-2003-0352 lineage)", Category: "RPC Service Enumeration Attempt"},
	{Port: ":3342", Product: "Azure SQL Managed Instance public endpoint", CVEs: "public data endpoint exposed", Category: "Database Exploitation Attempt"},
	{Port: ":6380", Product: "Azure Cache for Redis (TLS)", CVEs: "public endpoint with leaked access key", Category: "Unauthenticated Data Store Access Attempt"},
	{Port: ":5671", Product: "Azure Service Bus / Event Hubs (AMQPS)", CVEs: "SAS key leaked in config", Category: "Message Queue Exploitation Attempt"},
	{Port: ":9093", Product: "Azure Event Hubs Kafka endpoint", CVEs: "SAS key leaked in config", Category: "Message Queue Exploitation Attempt"},
	{Port: ":10255", Product: "Azure Cosmos DB for MongoDB API", CVEs: "connection string leaked", Category: "Database Exploitation Attempt"},
	{Port: ":19000", Product: "Service Fabric client connection endpoint", CVEs: "unauthenticated cluster client port", Category: "Cluster Management Takeover Attempt"},
}

var azureUDPDecoys = []udpDecoy{
	{":4500", "Azure VPN Gateway IPsec NAT-T", "VPN fingerprinting / IKE probing", "VPN Fingerprinting Probe"},
	{":3391", "RD Gateway UDP transport", "CVE-2020-0609,CVE-2020-0610", "RD Gateway Exploitation Probe"},
}
