package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/myth815/xray-rules-updater/internal/syncer"
	"github.com/myth815/xray-rules-updater/internal/verify"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
)

var version = "dev"

func main() {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(96 << 20)
	configPath := flag.String("config", "/config/config.json", "configuration file")
	verifyPath := flag.String("verify-config", "", "native verification configuration file")
	healthPath := flag.String("health-config", "", "live consumer health configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *healthPath != "" {
		body, err := os.ReadFile(*healthPath)
		if err != nil {
			fail("health configuration read failed")
		}
		config, err := verify.LoadHealthConfig(body)
		if err != nil {
			fail("health configuration invalid")
		}
		summary, err := verify.Health(ctx, config)
		_ = json.NewEncoder(os.Stdout).Encode(summary)
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if *verifyPath != "" {
		body, err := os.ReadFile(*verifyPath)
		if err != nil {
			fail("verification configuration read failed")
		}
		config, err := verify.LoadConfig(body)
		if err != nil {
			fail("verification configuration invalid")
		}
		summary, err := verify.Run(ctx, config)
		_ = json.NewEncoder(os.Stdout).Encode(summary)
		if err != nil {
			os.Exit(1)
		}
		return
	}
	body, err := os.ReadFile(*configPath)
	if err != nil {
		fail("configuration read failed")
	}
	if len(body) > 1<<20 {
		fail("configuration exceeds size limit")
	}
	absolute, err := filepath.Abs(*configPath)
	if err != nil {
		fail("configuration path invalid")
	}
	config, err := syncer.LoadConfig(body, filepath.Dir(absolute))
	if err != nil {
		fail(err.Error())
	}
	config.GeneratorVersion = version
	summary, err := syncer.Run(ctx, config)
	if err != nil {
		summary.Error = "run failed; current publication preserved"
		if summary.Status == "published_durability_uncertain" {
			summary.Error = "publication committed; directory durability unconfirmed"
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(summary)
	if err != nil {
		os.Exit(1)
	}
}
func fail(message string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "failed", "error": message})
	os.Exit(1)
}
