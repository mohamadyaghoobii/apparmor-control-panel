# 🛡️ AppArmor — The Practical, Distro‑Friendly Guide (with Debian/Ubuntu focus)

This README is written for people who want to **use AppArmor in real systems**: understand the model, know what the default behavior is on popular distros, and confidently operate profiles without breaking production.

---

## 📚 Table of contents

- 🧠 What AppArmor is (and why it matters)
- 🏛️ Origins & the “NSA” confusion
- ⚙️ How AppArmor works (LSM + profiles)
- 🗂️ Where profiles live (and what those folders mean)
- 🔥 Modes explained (Enforce / Complain / Unconfined)
- 🧩 “Defaults” on Ubuntu vs Debian vs other distros
- 📦 Installation & enabling (what is really required)
- 🧰 Essential commands you’ll actually use
- 🧾 Logging & troubleshooting
- 🆚 AppArmor vs SELinux (when to choose what)
- ✅ Operational best practices
- 🔗 Sources

---

## 🧠 What AppArmor is (and why it matters)

**AppArmor is a Linux Security Module (LSM) that enforces per‑application Mandatory Access Control (MAC) policies using profiles.**  
In plain English: you can tell the kernel, “This program may read these paths, write those paths, bind these ports, and nothing else.”

It is designed to **reduce blast radius** when a service gets exploited (RCE, plugin bug, deserialization, path traversal, etc.). Ubuntu documentation describes it as an “easy-to-use” LSM and explicitly frames it as MAC that supplements the Unix DAC model.

---

## 🏛️ Origins & the “NSA” confusion

### ✅ AppArmor is not an NSA project
A common myth is “AppArmor is made by NSA.” That’s a mix‑up.

### ✅ SELinux has NSA origins
Red Hat documentation states SELinux was originally a development project from the U.S. National Security Agency (NSA) and others.

### ✅ AppArmor’s origin story (short and accurate)
AppArmor originated in the Immunix ecosystem and later became “AppArmor powered by Immunix” in Novell documentation. Modern AppArmor is maintained and documented heavily by Canonical/Ubuntu, and it is upstreamed as part of Linux.

---

## ⚙️ How AppArmor works (LSM + profiles)

AppArmor is implemented through Linux’s LSM framework:

- The **kernel** enforces decisions.
- **User space tools** load profiles into the kernel.
- A profile describes what a program can do.

Important kernel perspective: the Linux kernel documentation explains that AppArmor restrictions apply only when policy is loaded into the kernel from user space, and kernel boot parameters can influence whether AppArmor is active.

---

## 🗂️ Where profiles live (and what those folders mean)

On Ubuntu (and commonly elsewhere), AppArmor profiles are stored in:

- `/etc/apparmor.d/`  
  Main profile directory.

Inside that tree you typically also see:

- `abstractions/`  
  Reusable building blocks that simplify profile authoring. Ubuntu Server documentation calls out abstractions (for shared libraries, journals, pseudo-devices, etc.).
- `tunables/`  
  Tunable variables (common patterns and paths).
- `local/`  
  Local overrides and site-specific adjustments (useful so package updates don’t overwrite your customizations).

---

## 🔥 Modes explained (Enforce / Complain / Unconfined)

AppArmor profiles have two primary modes:

### ✅ Enforce mode
- Policy is enforced.
- Rule violations are blocked and logged.

### 🧪 Complain mode
- Policy is not enforced.
- Violations are allowed but logged (great for learning and tuning).

Debian’s documentation describes the enforce/complain behavior clearly, and Ubuntu documentation explains enforcing vs complain and that reporting happens via syslog or audit.

### 🧍 Unconfined
A process is “unconfined” when:
- no profile applies to it, or
- its profile is disabled / not loaded.

This isn’t a “mode you set” as much as it is a “state you observe.”

---

## 🧩 “Defaults” on Ubuntu vs Debian vs other distros

The honest truth is: **defaults depend on your distro and what packages you installed.**  
But here are the parts that are explicitly documented:

### Ubuntu defaults
Ubuntu Server documentation explicitly says **AppArmor is installed and loaded by default on Ubuntu**, and recommends verifying using `aa-status`.

### Debian defaults
Debian’s own wiki states that **if you are using Debian 10 (Buster) or newer, AppArmor is enabled by default**, and provides bootloader steps for systems where you must explicitly enable it.

So it’s not “AppArmor is best on Debian.”  
It’s: **Debian/Ubuntu provide a very smooth operational path and documentation story**, and many people run AppArmor there because it’s already part of the default posture.

### Other distros (high-level)
- SUSE/SLES historically shipped AppArmor heavily, with strong documentation (including profile types and concepts like hats).
- Other distros may use SELinux by default, but AppArmor may still be available.

---

## 📦 Installation & enabling (what is really required)

### 1) Install user-space tooling
On Debian/Ubuntu, the standard packages are:

- `apparmor`
- `apparmor-utils`

### 2) Ensure the service is running
You typically enable the AppArmor service and verify status.

### 3) Ensure the kernel is actually enforcing AppArmor
Sometimes AppArmor is already enabled by default (Ubuntu, Debian 10+ commonly).
If not, your bootloader/kernel parameters may need configuration.

The Debian wiki shows a typical approach of adding kernel parameters for AppArmor enabling.
The Linux kernel docs also discuss enabling/disabling through kernel command line parameters.

---

## 🧰 Essential commands you’ll actually use

### Check status
```bash
sudo aa-status
```

### Switch a profile into Enforce
```bash
sudo aa-enforce /etc/apparmor.d/<profile-file>
```

### Switch a profile into Complain
```bash
sudo aa-complain /etc/apparmor.d/<profile-file>
```

### Reload a profile after editing
```bash
sudo apparmor_parser -r /etc/apparmor.d/<profile-file>
```

### Check service
```bash
sudo systemctl status apparmor
```

---

## 🧾 Logging & troubleshooting

### Where denials appear
Common places include:
- system logs (syslog/journal)
- audit logs if audit is enabled

Ubuntu security documentation notes policy violation reporting via syslog or audit.

### Quick log view examples
```bash
sudo journalctl -k | grep -i apparmor | tail -n 120
```

```bash
sudo grep -i apparmor /var/log/audit/audit.log | tail -n 120
```

### If something breaks in Enforce
Recommended approach:
- switch the profile to Complain
- reproduce the action
- review logs for denials
- minimally grant only what’s needed
- return to Enforce

---

## 🆚 AppArmor vs SELinux (when to choose what)

Both are MAC systems enforced by the kernel via LSM.

### AppArmor: path-based, often smoother onboarding
- Profiles are generally written around file paths and program paths.
- Very common on Ubuntu and Debian deployments.

### SELinux: label-based, powerful in strict policy models
- SELinux uses labels/contexts instead of just paths.
- Red Hat documentation explicitly calls out the NSA origin history of SELinux.

Pick what matches:
- your distro defaults and team expertise
- your compliance goals
- your operational constraints (how often things change, how complex your service graph is)

---

## ✅ Operational best practices (the “don’t break prod” section)

- Start new profiles in **Complain**.
- Use realistic workloads and tests (including edge cases).
- Prefer “least privilege” rules and avoid broad allow rules.
- Keep site-specific changes in local override patterns where possible.
- After updates, watch logs for new denials.
- Treat AppArmor like an operational control: monitor, tune, iterate.

---

## 🔗 Sources

These are the primary sources used to align statements in this README with real documentation:

- Ubuntu Server docs: AppArmor is installed and loaded by default; `aa-status` verification; profile directory and abstractions  
  https://documentation.ubuntu.com/server/how-to/security/apparmor/

- Ubuntu Security docs: enforcing vs complain; violations reported via syslog or audit; general AppArmor overview  
  https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/

- Debian Wiki: Debian 10+ enabled by default; bootloader steps; enforce vs complain description  
  https://wiki.debian.org/AppArmor/HowToUse

- Linux kernel docs: AppArmor LSM admin guide; kernel command-line parameters and policy loading concepts  
  https://www.kernel.org/doc/html/latest/admin-guide/LSM/apparmor.html

- SUSE docs: profile types (standard, local, hats, etc.)  
  https://documentation.suse.com/

- Red Hat docs: SELinux history and NSA origin statement  
  https://docs.redhat.com/
