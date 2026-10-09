package main

import "embed"

// All assets are embedded into the binary at build time, so the compiled
// release binary is fully self-contained: no accompanying directories are
// needed on the server it's deployed to.

//go:embed assets/static
var staticFS embed.FS

//go:embed assets/uploads
var uploadsFS embed.FS

//go:embed assets/dotenv.txt
var envFileContent []byte
