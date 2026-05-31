package kula

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionData string

var Version = strings.TrimSpace(versionData)
