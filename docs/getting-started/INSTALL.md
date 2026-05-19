# Installation Guide
> **Deploying Maknoon across Industrial Environments**

Maknoon is distributed as a single, statically linked binary with zero external dependencies (CGO-free).

---

## 🍺 Homebrew (macOS / Linux)
The recommended way to install Maknoon on personal workstations.
```bash
brew install al-Zamakhshari/tap/maknoon
```

## 📦 Binary Downloads
Download the latest pre-compiled binaries from the [GitHub Releases](https://github.com/al-Zamakhshari/maknoon/releases) page.
1.  Choose your architecture (`amd64`, `arm64`).
2.  Move the binary to `/usr/local/bin/maknoon`.
3.  Ensure it's executable: `chmod +x /usr/local/bin/maknoon`.

## 🐳 Docker (Industrial Sandbox)
For cloud deployments and automated agents, use the multi-stage `scratch` build (~13MB).
```bash
docker pull ghcr.io/al-zamakhshari/maknoon:latest
```

## 🛠️ Build from Source
Requires Go 1.22+.
```bash
git clone https://github.com/al-Zamakhshari/maknoon
cd maknoon
make build
```

---

## 🛡️ Hardware Hardening Setup
After installation, it is highly recommended to configure your hardware trust anchors:
*   **[TPM 2.0 Setup](./HARDWARE-HARDENING.md)**: Binding identities to silicon trust and secure deletion guidance for SSDs.
