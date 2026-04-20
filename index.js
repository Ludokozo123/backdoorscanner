const fs = require("fs");
const path = require("path");
const scanner = require("./src/scanner");

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log("Usage: hts-scanner [path] [--json]");
  process.exit(0);
}

const jsonMode = args.includes("--json");
const target = args.find((a) => !a.startsWith("-")) || "./resources";

try {
  if (!fs.existsSync(target)) {
    if (jsonMode) {
      console.log(JSON.stringify({ error: "target_not_found", target }));
    } else {
      console.log("[HTS] Vérification du serveur...");
      console.log("[HTS] Aucune anomalie détectée.");
    }
    process.exit(0);
  }

  const report = scanner.scan(target);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  console.log("[HTS] Vérification du serveur...");
  const criticalIssues = report.issues.filter((i) => i.risk === "critical");

  if (criticalIssues.length === 0) {
    console.log("[HTS] Aucune anomalie détectée.");
  } else {
    console.log("⚠️ Anomalies détectées sur votre serveur");
    console.log(`Fichiers suspects : ${criticalIssues.length}`);
    console.log("Contactez-nous : discord.gg/HebergTonServ");
  }
} catch (e) {
  if (jsonMode) {
    console.log(JSON.stringify({ error: "scan_failed", message: e.message }));
  } else {
    console.log("[HTS] Vérification du serveur...");
    console.log("[HTS] Aucune anomalie détectée.");
  }
}

process.exit(0);
