# malscan

A Bash utility that installs or updates [ClamAV](https://www.clamav.net/) and Maldet (Linux Malware Detect), updates signatures, and scans a selected directory on supported Ubuntu LTS releases.

## Requirements

- Ubuntu 24.04 LTS or 26.04 LTS
- Bash
- Root privileges
- Internet access for package installation and signature updates

## Usage

```bash
sudo bash malscan.sh [OPTIONS] [scan_directory]
```

The default scan mode is `--all`, and the default directory is `/home`:

```bash
sudo bash malscan.sh
```

## Options

| Short option | Long option | Behavior |
|---|---|---|
| `-c` | `--clamav` | Run the ClamAV scan only |
| `-m` | `--maldet` | Run the Maldet scan only |
| `-a` | `--all` | Run both ClamAV and Maldet; this is the default |
| `-h` | `--help` | Display usage information |

## Examples

Scan `/home` with both engines:

```bash
sudo bash malscan.sh
sudo bash malscan.sh --all /home
```

Scan `/tmp/test-directory` with ClamAV only:

```bash
sudo bash malscan.sh -c /tmp/test-directory
sudo bash malscan.sh --clamav /tmp/test-directory
```

Scan `/var/www` with Maldet only:

```bash
sudo bash malscan.sh -m /var/www
sudo bash malscan.sh --maldet /var/www
```

Scan the entire filesystem with both engines:

```bash
sudo bash malscan.sh -a /
sudo bash malscan.sh --all /
```

The short and long switch forms are equivalent. Use only one engine switch for a single-engine scan.

## Logs

Scan and update logs are stored in `/var/log/malscan/`.

## Validation

Run a Bash syntax check and ShellCheck before use:

```bash
bash -n malscan.sh
shellcheck malscan.sh
```
