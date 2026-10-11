package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"homegate.local/homegate/internal/access"

	"homegate.local/homegate/internal/api"
	"homegate.local/homegate/internal/app"
	"homegate.local/homegate/internal/certimport"
	"homegate.local/homegate/internal/frontend"
	"homegate.local/homegate/internal/logger"
)

var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, "usage: homegate <version|selftest|dns-check-private <private-file>|status|recovery-status|check|network-resolve|dns-provider-catalog|dns-provider-status <account-id>|dns-zones <account-id>|acme-ca-catalog|acme-ca-status <ca> [environment]|ddns-status|ddns-sync [rule-id]|ddns-delete <rule-id>|cert-status|cert-renew [cert-id]|cert-import <cert-id> <cert-file> <key-file>|proxy-status|access-status|access-update <region>|access-refresh <region>|access-recent|access-clear-all|access-clear-entry <ip> <host>|access-clear-denied|access-validate-file <path>|log-events [max-lines]|firewall-status|firewall-apply|firewall-cleanup|wol-status|wol <host-id>|wol <interface> <mac>|daemon>")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	a := app.New(version)
	ctx := context.Background()

	switch os.Args[1] {
	case "dns-check-private":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report := frontend.PrivateDNSCheck(ctx, os.Args[2])
		api.WriteJSON(os.Stdout, report)
		if report["ok"] != true {
			os.Exit(1)
		}

	case "selftest":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report := frontend.SelfTest(ctx, version)
		api.WriteJSON(os.Stdout, report)
		if !report.OK {
			os.Exit(1)
		}

	case "web-read", "web-submit":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		request, err := frontend.ReadRequest(os.Args[2])
		if err != nil {
			api.WriteJSON(os.Stdout, map[string]any{"ok": false, "error": "Invalid request file"})
			os.Exit(1)
		}
		if os.Args[1] == "web-read" {
			request.Write = false
			api.WriteJSON(os.Stdout, (frontend.Engine{Host: &frontend.OSHost{}, Version: version}).Run(ctx, request))
		} else {
			request.Write = true
			result, err := (frontend.JobStore{Root: "/tmp/homegate-frontend-jobs"}).Submit(request)
			if err != nil {
				result = frontend.JobStatus{Error: "Unable to queue action"}
			}
			api.WriteJSON(os.Stdout, result)
		}
	case "web-job":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		if err := (frontend.JobStore{Root: "/tmp/homegate-frontend-jobs"}).Work(ctx, os.Args[2], frontend.Engine{Host: &frontend.OSHost{}, Version: version}); err != nil {
			os.Exit(1)
		}
	case "web-job-status", "web-job-ack":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		api.WriteJSON(os.Stdout, (frontend.JobStore{Root: "/tmp/homegate-frontend-jobs"}).Status(os.Args[2], os.Args[1] == "web-job-ack"))

	case "version":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, map[string]any{"api_version": api.Version, "version": version, "arch": runtime.GOARCH}); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.Status(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "recovery-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.RecoveryStatus()); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "network-resolve":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.NetworkStatus(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "dns-provider-catalog":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.DNSProviderCatalog()); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "acme-ca-catalog":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.ACMECACatalog()); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "acme-ca-status":
		if len(os.Args) != 3 && len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		environment := "production"
		if len(os.Args) == 4 {
			environment = os.Args[3]
		}
		report, caErr := a.ACMECACheck(ctx, os.Args[2], environment)
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if caErr != nil {
			os.Exit(1)
		}
	case "dns-provider-status":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report, providerErr := a.DNSProviderStatus(ctx, os.Args[2])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if providerErr != nil {
			os.Exit(1)
		}
	case "dns-zones":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report, zonesErr := a.DNSZones(ctx, os.Args[2])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if zonesErr != nil {
			os.Exit(1)
		}
	case "ddns-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.DDNSReport()); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "ddns-sync":
		if len(os.Args) > 3 {
			usage()
			os.Exit(2)
		}
		ruleID := ""
		if len(os.Args) == 3 {
			ruleID = os.Args[2]
		}
		report, syncErr := a.SyncDDNS(ctx, ruleID)
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if syncErr != nil {
			os.Exit(1)
		}
	case "ddns-delete":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report, deleteErr := a.DeleteDDNS(ctx, os.Args[2])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if deleteErr != nil {
			os.Exit(1)
		}
	case "cert-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.CertificateStatus(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "cert-renew":
		if len(os.Args) > 3 {
			usage()
			os.Exit(2)
		}
		if len(os.Args) == 3 {
			report, renewErr := a.RenewCertificate(ctx, os.Args[2])
			if err := api.WriteJSON(os.Stdout, report); err != nil {
				app.Fatalf("homegate: %v", err)
				os.Exit(1)
			}
			if renewErr != nil {
				os.Exit(1)
			}
		} else {
			report := a.RenewDueCertificates(ctx)
			if err := api.WriteJSON(os.Stdout, report); err != nil {
				app.Fatalf("homegate: %v", err)
				os.Exit(1)
			}
			if !report.OK {
				os.Exit(1)
			}
		}
	case "cert-import":
		if len(os.Args) != 5 {
			usage()
			os.Exit(2)
		}
		report, importErr := certimport.Import(a.HomeDir, version, os.Args[2], os.Args[3], os.Args[4])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if importErr != nil {
			os.Exit(1)
		}
	case "proxy-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.ProxyStatus(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "access-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.AccessStatus(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "access-update":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report, updateErr := a.UpdateAccessRegion(ctx, os.Args[2])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if updateErr != nil {
			os.Exit(1)
		}
	case "access-refresh":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		report, updateErr := a.RefreshAccessRegion(ctx, os.Args[2])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if updateErr != nil {
			os.Exit(1)
		}
	case "access-recent":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.AccessRecent(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "access-clear-all":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report, clearErr := a.ClearAccessRecent()
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if clearErr != nil {
			os.Exit(1)
		}
	case "access-clear-entry":
		if len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		report, clearErr := a.ClearAccessRecentEntry(os.Args[2], os.Args[3])
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if clearErr != nil {
			os.Exit(1)
		}
	case "access-clear-denied":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report, clearErr := a.ClearDeniedAccessRecent()
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if clearErr != nil {
			os.Exit(1)
		}
	case "access-validate-file":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			_ = api.WriteJSON(os.Stdout, map[string]any{"api_version": api.Version, "ok": false, "phase": "access", "error": err.Error()})
			os.Exit(1)
		}
		normalized, err := access.NormalizeAllow(string(b))
		if err != nil {
			_ = api.WriteJSON(os.Stdout, map[string]any{"api_version": api.Version, "ok": false, "phase": "access", "error": err.Error()})
			os.Exit(1)
		}
		prefixes, _ := access.ParseAllow(normalized)
		if err := api.WriteJSON(os.Stdout, map[string]any{"api_version": api.Version, "ok": true, "phase": "access", "normalized": normalized, "count": len(prefixes)}); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "log-events":
		if len(os.Args) != 2 && len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		maxLines := 1024
		if len(os.Args) == 3 {
			v, err := strconv.Atoi(os.Args[2])
			if err != nil || v < 1 || v > 20000 {
				usage()
				os.Exit(2)
			}
			maxLines = v
		}
		if err := api.WriteJSON(os.Stdout, logger.ReadEvents(logger.DefaultPath, version, maxLines)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "firewall-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.FirewallStatus()); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "firewall-apply":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report, applyErr := a.ApplyFirewall(ctx)
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if applyErr != nil {
			os.Exit(1)
		}
	case "firewall-cleanup":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report := a.CleanupFirewall(ctx)
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if !report.OK {
			os.Exit(1)
		}
	case "wol-status":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := api.WriteJSON(os.Stdout, a.WOLStatus(ctx)); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
	case "wol":
		if len(os.Args) != 3 && len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		var reportErr error
		var report any
		if len(os.Args) == 3 {
			r, err := a.WakeWOLHost(ctx, os.Args[2])
			report, reportErr = r, err
		} else {
			r, err := a.WakeWOLDirect(ctx, os.Args[2], os.Args[3])
			report, reportErr = r, err
		}
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if reportErr != nil {
			os.Exit(1)
		}
	case "check":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		report, checkErr := a.Check(ctx)
		if err := api.WriteJSON(os.Stdout, report); err != nil {
			app.Fatalf("homegate: %v", err)
			os.Exit(1)
		}
		if checkErr != nil {
			os.Exit(app.ExitCode(checkErr))
		}
	case "daemon":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := a.RunDaemon(ctx); err != nil {
			app.Fatalf("homegate daemon: %v", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}
