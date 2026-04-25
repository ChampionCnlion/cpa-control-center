//go:build !web && !windows && !darwin

package main

import "github.com/wailsapp/wails/v2/pkg/options"

func applyPlatformOptions(appOptions *options.App) {
	_ = appOptions
}
