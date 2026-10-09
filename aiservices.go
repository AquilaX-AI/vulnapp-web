package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// startAIServices fakes the AI/LLM infrastructure stack that's become
// the newest major category of "spun it up, forgot auth" exposure as of
// 2026: Ollama (model-serving API), unauthenticated MCP servers, and
// vector databases (ChromaDB, Milvus). Real research backing each one:
//
//   - Ollama: SentinelLABS/Censys counted ~175,000 publicly exposed
//     instances in early 2026; real CVEs include CVE-2024-37032
//     ("Probllama", path traversal -> RCE as root) and CVE-2026-7482
//     ("Bleeding Llama", unauthenticated memory leak, ~300k servers).
//   - MCP servers: the "Operation Bizarre Bazaar" campaign (Sysdig/
//     Pillar Security, Feb 2026) scanned for exactly this alongside
//     Ollama, checking capability manifests for filesystem/shell/
//     database/cloud access.
//   - ChromaDB: CVE-2026-45829 ("ChromaToast"), CVSS 10.0 pre-auth RCE,
//     reportedly affecting most internet-exposed instances.
//   - Milvus: CVE-2026-26190, unauthenticated REST API on the
//     metrics/management port.
func startAIServices() {
	startFakeHTTPService(":11434", handleFakeOllama)
	startFakeHTTPService(":6277", handleFakeMCPServer)
	startFakeHTTPService(":8000", handleFakeChromaDB)
	startFakeHTTPService(":9091", handleFakeMilvus)
}

// handleFakeOllama mimics Ollama's real, genuinely-unauthenticated-by-
// default API: the root path literally returns "Ollama is running" on a
// real server, /api/tags lists locally-pulled models (recon: what's
// available to abuse), /api/generate serves a fake inference response
// (modeling LLMjacking - using someone else's GPU for free), and
// /api/pull models the model-theft vector those exposure reports
// describe.
func handleFakeOllama(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/":
		fmt.Fprint(w, "Ollama is running")

	case r.URL.Path == "/api/tags":
		log.Printf("%s Ollama model inventory requested [T1595.002 Active Scanning: Vulnerability Scanning | AI Model Inventory Reconnaissance Attempt]", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[
  {"name":"llama3:70b","model":"llama3:70b","size":39969265228,"digest":"a1b2c3d4e5f6"},
  {"name":"acme-support-finetune:latest","model":"acme-support-finetune:latest","size":4920739328,"digest":"f6e5d4c3b2a1"}
]}`)

	case r.URL.Path == "/api/pull":
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		log.Printf("%s Ollama model pull/exfiltration attempt: %q [T1005 Data from Local System | AI Model Theft Attempt]", r.RemoteAddr, body.Name)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success"}`)

	case r.URL.Path == "/api/generate" || r.URL.Path == "/api/chat":
		log.Printf("%s Ollama inference request (unauthenticated) [T1496 Resource Hijacking | LLMjacking / Unauthorized Inference Resource Abuse]", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"model":"llama3:70b","response":"Sure, I can help with that.","done":true}`)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleFakeMCPServer mimics an unauthenticated Model Context Protocol
// server's JSON-RPC endpoint. tools/list is the actual recon signal real
// campaigns check for: a capability manifest revealing filesystem,
// shell, database, and cloud access that an MCP-aware client (or the
// AI agent driving it) could invoke with no authentication at all.
func handleFakeMCPServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
		ID     any    `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")

	switch req.Method {
	case "initialize":
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"acme-internal-mcp","version":"0.3.1"}}}`, req.ID)

	case "tools/list":
		log.Printf("%s MCP capability manifest requested (filesystem/shell/db/cloud tools exposed) [T1595.002 Active Scanning: Vulnerability Scanning | Unauthenticated MCP Server Capability Discovery Attempt]", r.RemoteAddr)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"tools":[
  {"name":"filesystem_read","description":"Read a file from the local filesystem"},
  {"name":"filesystem_write","description":"Write a file to the local filesystem"},
  {"name":"execute_shell_command","description":"Run a shell command and return its output"},
  {"name":"database_query","description":"Run a SQL query against the production database"},
  {"name":"cloud_api_call","description":"Call the configured cloud provider's API with stored credentials"}
]}}`, req.ID)

	case "tools/call":
		log.Printf("%s MCP tool invocation attempted [T1059 Command and Scripting Interpreter | MCP Tool Invocation (Remote Code Execution) Attempt]", r.RemoteAddr)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"error":{"code":-32601,"message":"tool execution disabled in this environment"}}`, req.ID)

	default:
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"error":{"code":-32601,"message":"method not found"}}`, req.ID)
	}
}

// handleFakeChromaDB mimics ChromaDB's real, unauthenticated-by-default
// REST API (CVE-2026-45829, CVSS 10.0 pre-auth RCE). The collections
// list is the actual data-exposure risk - these contain whatever
// documents/embeddings a RAG pipeline indexed, frequently including
// sensitive internal documents.
func handleFakeChromaDB(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v2/heartbeat":
		fmt.Fprint(w, `{"nanosecond heartbeat": 1234567890123456}`)
	case "/api/v1/version":
		fmt.Fprint(w, `"1.0.12"`)
	case "/api/v1/collections":
		log.Printf("%s ChromaDB collection list requested (unauthenticated) [T1213 Data from Information Repositories | Unauthenticated Vector Database Access Attempt]", r.RemoteAddr)
		fmt.Fprint(w, `[
  {"name":"customer_support_embeddings","id":"a1b2c3d4-0000-0000-0000-000000000001"},
  {"name":"internal_wiki_embeddings","id":"a1b2c3d4-0000-0000-0000-000000000002"}
]`)
	default:
		fmt.Fprint(w, `{"nanosecond heartbeat": 1234567890123456}`)
	}
}

// handleFakeMilvus mimics the real finding behind CVE-2026-26190: the
// full Milvus REST API registered on the metrics/management port
// (9091) with no authentication, exposing data manipulation and
// credential management alongside the health/metrics endpoints that
// port is actually meant for.
func handleFakeMilvus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/healthz":
		fmt.Fprint(w, "OK")
	case "/api/v1/collection":
		log.Printf("%s Milvus unauthenticated management API access (metrics port) [T1213 Data from Information Repositories | Unauthenticated Vector Database Management API Access Attempt]", r.RemoteAddr)
		fmt.Fprint(w, `{"collection_name":"product_embeddings","status":{"error_code":0}}`)
	default:
		fmt.Fprint(w, `{"version":"2.4.1"}`)
	}
}
