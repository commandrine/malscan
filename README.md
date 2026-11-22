# malscan

Script to install or update ClamAV and Maldet, update signatures, and scan a selected directory on supported Ubuntu LTS releases.

```bash
sudo bash malscan.sh /home
sudo bash malscan.sh --clamav /tmp/test-directory
sudo bash malscan.sh --maldet /var/www
sudo bash malscan.sh --all /
```

Supported Ubuntu releases:

- Ubuntu 24.04 LTS
- Ubuntu 26.04 LTS

Run ShellCheck and a Bash syntax check before use:

```bash
bash -n malscan.sh
shellcheck malscan.sh
```
