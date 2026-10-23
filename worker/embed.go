// Package worker embeds the Cloudflare Worker script so the setup command can
// deploy it without a separate download or build step.
package worker

import _ "embed"

//go:embed src/index.js
var Script string
