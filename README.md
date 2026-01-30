# 🧪 WordPress on Upsun: Experimental Configuration

> **⚠️ WARNING: CONCEPT / EXPERIMENT**
> This repository is a **Public Archive of Experiments**.
> It is **NOT a tutorial** and **NOT intended for production use** as-is.
> Use these snippets at your own risk for educational purposes or as inspiration for your own setups.

## 📂 Overview

This repository contains the result of an R&D session focused on hardening and optimizing a WordPress **Bedrock** architecture hosted on **Upsun (Platform.sh)**.

The goal was to push the logic of "Infrastructure as Code" to the limit without relying on heavy plugins for tasks that the server handles better.

## 📄 Contents

### 1. `.upsun/config.yaml` (Optimized)
A highly opinionated configuration file for Upsun containers.
*   **Dynamic CSP**: Switches Content Security Policy from `Report-Only` (Dev) to `Strict` (Prod).
*   **Hardened Security**: Blocks execution of PHP in uploads, sensitive file extensions (`.env`, `.log`, `.sql`), and XML-RPC/REST User Enumeration at the router level (Nginx).
*   **Modern Headers**: Implementation of `Permissions-Policy`, HSTS, `Referrer-Policy`, and `X-Frame-Options`.
*   **Performance**: OPcache tuned for immutable deployments (`validate_timestamps=0`).
*   **Smart Hooks**: Conditional logic for build/deploy steps based on environment variables.

### 2. `web/app/mu-plugins/` (Must-Use Plugins)

#### `health-check.php`
A lightweight monitoring endpoint designed for zero-downtime deployments.
*   **Concept**: Verifies critical services (PHP, MySQL, Redis) *without* loading the entire WordPress core.
*   **Usage**: Point your uptime monitor to `https://yoursite.com/health`.

#### `upsun-security.php`
Advanced security hardening for WordPress in a PaaS environment.
*   **Context**: Implements defense-in-depth strategies tailored for read-only filesystems.


## 🛠️ Context
These files were generated during a "Deep Coding" session exploring how to apply **Defense in Depth** principles to a PaaS environment. The focus was on shifting security responsibilites from the application layer (PHP Plugins) to the infrastructure layer (Container Config).

## 🚫 Disclaimer
This code is provided "as is". It reflects a specific configuration snapshot and may require adjustments to work with your specific stack or Upsun's evolving platform version.
