#!/bin/bash

################################################################################
# Malware Scanner Setup and Execution Script
#
# Installs and configures ClamAV and Maldet on supported Ubuntu systems,
# updates signatures, and scans a selected directory.
################################################################################

set -Eeuo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCAN_DIRECTORY="/home"
LOG_DIR="/var/log/malscan"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
MALDET_REPO="https://github.com/rfxn/linux-malware-detect.git"
MALDET_INSTALL_DIR="/usr/local/maldetect"
MALDET_CLONE_DIR="/tmp/linux-malware-detect"

SCAN_CLAMAV=false
SCAN_MALDET=false

log_info() { printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$*"; }
log_success() { printf '%b[SUCCESS]%b %s\n' "$GREEN" "$NC" "$*"; }
log_warning() { printf '%b[WARNING]%b %s\n' "$YELLOW" "$NC" "$*"; }
log_error() { printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$*"; }
result_ok() { printf '%b✓ %s%b\n' "$GREEN" "$*" "$NC"; }
result_alert() { printf '%b⚠ %s%b\n' "$RED" "$*" "$NC"; }

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)."
        exit 1
    fi
}

show_help() {
    cat <<'EOF'
Malware Scanner Setup and Execution Script

Usage: sudo bash malscan.sh [OPTIONS] [scan_directory]

Options:
  -c, --clamav       Run ClamAV scan only
  -m, --maldet       Run Maldet scan only
  -a, --all          Run both ClamAV and Maldet scans (default)
  -h, --help         Display this help message

Arguments:
  scan_directory     Directory to scan (default: /home)

Examples:
  sudo bash malscan.sh /home
  sudo bash malscan.sh -c /home
  sudo bash malscan.sh -m /var/www
  sudo bash malscan.sh -a /
EOF
}

parse_arguments() {
    local scan_mode="all"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--clamav) scan_mode="clamav"; shift ;; 
            -m|--maldet) scan_mode="maldet"; shift ;; 
            -a|--all) scan_mode="all"; shift ;; 
            -h|--help) show_help; exit 0 ;; 
            -* ) log_error "Unknown option: $1"; show_help; exit 1 ;; 
            *) SCAN_DIRECTORY="$1"; shift ;;
        esac
    done

    case "$scan_mode" in
        clamav) SCAN_CLAMAV=true; SCAN_MALDET=false ;;
        maldet) SCAN_CLAMAV=false; SCAN_MALDET=true ;;
        all) SCAN_CLAMAV=true; SCAN_MALDET=true ;;
    esac
}

prepare_system() {
    log_info "Preparing system package lists..."
    apt-get update -qq
    log_success "Package lists updated"
}

install_clamav() {
    if command_exists clamscan && command_exists freshclam; then
        log_info "ClamAV is already installed"
        return 0
    fi

    log_info "Installing ClamAV via apt..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-daemon clamav-freshclam

    if ! command_exists clamscan || ! command_exists freshclam; then
        log_error "ClamAV installation completed but required binaries are missing"
        return 1
    fi

    log_success "ClamAV installed successfully"
}

update_clamav_signatures() {
    log_info "Updating ClamAV signatures..."

    local freshclam_was_running=false
    if command_exists systemctl && systemctl is-active --quiet clamav-freshclam; then
        freshclam_was_running=true
        systemctl stop clamav-freshclam
    fi

    if freshclam --stdout; then
        log_success "ClamAV signatures updated"
    else
        log_warning "ClamAV signature update encountered an issue; continuing with installed signatures"
    fi

    if [[ "$freshclam_was_running" == true ]]; then
        systemctl start clamav-freshclam || log_warning "Could not restart clamav-freshclam"
    fi
}

install_maldet() {
    if command_exists maldet && [[ -x "${MALDET_INSTALL_DIR}/maldet" ]]; then
        log_info "Maldet is already installed at $(command -v maldet)"
        return 0
    fi

    log_info "Installing Linux Malware Detector from its official GitHub repository"
    DEBIAN_FRONTEND=noninteractive apt-get install -y git perl curl

    rm -rf "$MALDET_CLONE_DIR"
    if ! git clone --depth 1 "$MALDET_REPO" "$MALDET_CLONE_DIR" >"${LOG_DIR}/maldet_clone.log" 2>&1; then
        log_error "Failed to clone Maldet; see ${LOG_DIR}/maldet_clone.log"
        return 1
    fi

    if [[ ! -x "$MALDET_CLONE_DIR/install.sh" ]]; then
        log_error "Maldet installer is missing or not executable"
        rm -rf "$MALDET_CLONE_DIR"
        return 1
    fi

    pushd "$MALDET_CLONE_DIR" >/dev/null
    set +e
    ./install.sh >"${LOG_DIR}/maldet_install.log" 2>&1
    local install_status=$?
    set -e
    popd >/dev/null

    rm -rf "$MALDET_CLONE_DIR"

    if (( install_status != 0 )); then
        log_error "Maldet installer failed with exit status $install_status"
        log_error "Installation log: ${LOG_DIR}/maldet_install.log"
        return 1
    fi

    if [[ -x "${MALDET_INSTALL_DIR}/maldet" ]]; then
        log_success "Maldet binary verified at ${MALDET_INSTALL_DIR}/maldet"
    else
        log_error "Maldet installer reported success but its binary was not found"
        return 1
    fi

    if ! command_exists maldet; then
        ln -sfn "${MALDET_INSTALL_DIR}/maldet" /usr/local/bin/maldet
        hash -r
    fi

    if ! command_exists maldet; then
        log_error "Maldet binary is not available in PATH"
        return 1
    fi

    log_success "Maldet installed successfully"
}

run_piped_command() {
    local log_file="$1"
    shift

    set +e
    "$@" 2>&1 | tee -a "$log_file"
    local status=${PIPESTATUS[0]}
    set -e
    return "$status"
}

update_maldet() {
    if ! command_exists maldet; then
        log_warning "Maldet is not installed; skipping update"
        return 0
    fi

    log_info "Updating Maldet engine and signatures..."

    if run_piped_command "${LOG_DIR}/maldet_update_ver_${TIMESTAMP}.log" maldet --update-ver; then
        log_success "Maldet engine version updated"
    else
        log_warning "Maldet engine update encountered an issue"
    fi

    if run_piped_command "${LOG_DIR}/maldet_update_sigs_${TIMESTAMP}.log" maldet --update-sigs; then
        log_success "Maldet signatures updated"
    else
        log_warning "Maldet signature update encountered an issue"
    fi
}

setup_logging() {
    log_info "Setting up logging directory..."
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    log_success "Logging directory created: $LOG_DIR"
}

process_clamav_results() {
    local clamav_log="$1"

    log_info ""
    log_info "=========================================="
    log_info "ClamAV Scan Results"
    log_info "=========================================="

    if [[ ! -f "$clamav_log" ]]; then
        log_warning "ClamAV log file not found: $clamav_log"
        return 1
    fi

    local known_viruses engine_version scanned_files infected_files data_scanned
    known_viruses=$(grep 'Known viruses' "$clamav_log" | tail -1 || true)
    engine_version=$(grep 'Engine version' "$clamav_log" | tail -1 || true)
    scanned_files=$(grep 'Scanned files' "$clamav_log" | tail -1 || true)
    infected_files=$(grep 'Infected files' "$clamav_log" | tail -1 || true)
    data_scanned=$(grep 'Data scanned' "$clamav_log" | tail -1 || true)

    [[ -n "$known_viruses" ]] && log_info "$known_viruses"
    [[ -n "$engine_version" ]] && log_info "$engine_version"
    [[ -n "$scanned_files" ]] && log_info "$scanned_files"
    [[ -n "$data_scanned" ]] && log_info "$data_scanned"

    if grep -q 'Infected files: 0' "$clamav_log"; then
        result_ok "No malware detected - Clean scan"
    elif [[ -n "$infected_files" ]]; then
        result_alert "$infected_files - REQUIRES REVIEW"
        grep -E 'FOUND|Detected' "$clamav_log" | while read -r line; do
            result_alert "$line"
        done || true
    else
        log_warning "Scan result could not determine infection count; review the full log"
        return 1
    fi

    log_info ""
}

process_maldet_results() {
    local maldet_log="$1"

    log_info "=========================================="
    log_info "Maldet Scan Results"
    log_info "=========================================="

    if [[ ! -f "$maldet_log" ]]; then
        log_warning "Maldet log file not found: $maldet_log"
        return 1
    fi

    local scan_completion scan_report malware_hits
    scan_completion=$(grep '{scan} scan completed' "$maldet_log" | tail -1 || true)
    scan_report=$(grep '{scan} scan report saved' "$maldet_log" | tail -1 || true)

    [[ -n "$scan_report" ]] && log_info "$scan_report"

    if [[ -z "$scan_completion" ]]; then
        log_warning "Maldet scan completion could not be confirmed; review the full log"
        log_info ""
        return 1
    fi

    log_info "$scan_completion"
    malware_hits=$(grep -oP 'malware hits \K[0-9]+' <<<"$scan_completion" | head -1 || true)

    if [[ -z "$malware_hits" ]]; then
        log_warning "Maldet malware-hit count could not be determined; review the full log"
        log_info ""
        return 1
    fi

    if [[ "$malware_hits" -eq 0 ]]; then
        result_ok "No malware detected - Clean scan"
    else
        result_alert "Malware detected: $malware_hits hit(s) found - REQUIRES REVIEW"
        grep -E 'SUSPECT|DETECTION' "$maldet_log" | while read -r line; do
            result_alert "$line"
        done || true
    fi

    log_info ""
}

perform_clamav_scan() {
    log_info "=========================================="
    log_info "Starting ClamAV scan"
    log_info "=========================================="

    local clamav_log="${LOG_DIR}/clamav_scan_${TIMESTAMP}.log"
    update_clamav_signatures

    log_info "Scanning $SCAN_DIRECTORY recursively with ClamAV"
    local scan_status=0
    if run_piped_command "$clamav_log" clamscan -r --infected "$SCAN_DIRECTORY"; then
        scan_status=0
    else
        scan_status=$?
    fi

    if (( scan_status == 0 )) || (( scan_status == 1 )); then
        process_clamav_results "$clamav_log"
    else
        log_error "ClamAV scan failed with exit status $scan_status"
        log_error "Review $clamav_log"
        return 1
    fi
}

perform_maldet_scan() {
    if ! command_exists maldet; then
        log_warning "Maldet is not available; skipping Maldet scan"
        return 1
    fi

    log_info "=========================================="
    log_info "Starting Maldet scan"
    log_info "=========================================="

    local maldet_log="${LOG_DIR}/maldet_scan_${TIMESTAMP}.log"
    update_maldet

    log_info "Scanning $SCAN_DIRECTORY with Maldet"
    local scan_status=0
    if run_piped_command "$maldet_log" maldet --scan-all "$SCAN_DIRECTORY"; then
        scan_status=0
    else
        scan_status=$?
    fi

    if (( scan_status == 0 )) || (( scan_status == 1 )); then
        process_maldet_results "$maldet_log"
    else
        log_error "Maldet scan failed with exit status $scan_status"
        log_error "Review $maldet_log"
        return 1
    fi
}

perform_scan() {
    local scan_dir="$1"
    local scan_failed=false

    if [[ ! -d "$scan_dir" ]]; then
        log_error "Scan directory does not exist: $scan_dir"
        return 1
    fi

    if [[ "$SCAN_CLAMAV" == true ]]; then
        perform_clamav_scan || scan_failed=true
    fi

    if [[ "$SCAN_MALDET" == true ]]; then
        perform_maldet_scan || scan_failed=true
    fi

    if [[ "$scan_failed" == true ]]; then
        log_warning "One or more requested scans failed or were incomplete"
        return 1
    fi

    log_success "All requested scans completed"
}

review_findings() {
    log_info "=========================================="
    log_info "Scan Summary and Next Steps"
    log_info "=========================================="

    if [[ "$SCAN_MALDET" == true ]] && command_exists maldet; then
        run_piped_command "${LOG_DIR}/maldet_reports_${TIMESTAMP}.log" maldet --report list ||
            log_warning "Could not retrieve Maldet scan reports"

        log_info "View a specific Maldet report: sudo maldet --report <report-id>"
        log_info "Quarantine a report: sudo maldet --quarantine <report-id>"
    fi

    if [[ "$SCAN_CLAMAV" == true ]]; then
        local latest_clamav
        latest_clamav=$(find "$LOG_DIR" -maxdepth 1 -name 'clamav_scan*.log' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)
        [[ -n "$latest_clamav" ]] && log_info "Latest ClamAV log: $latest_clamav"
    fi

    log_info "All scan logs are in: $LOG_DIR"
}

main() {
    parse_arguments "$@"

    log_info "=========================================="
    log_info "Malware Scanner Setup and Execution"
    log_info "=========================================="
    log_info "Scan directory: $SCAN_DIRECTORY"
    log_info "Log directory: $LOG_DIR"

    check_root

    setup_logging

    local engines_str=""
    [[ "$SCAN_CLAMAV" == true ]] && engines_str="ClamAV"
    if [[ "$SCAN_MALDET" == true ]]; then
        [[ -n "$engines_str" ]] && engines_str+=", "
        engines_str+="Maldet"
    fi
    log_info "Scan engines: $engines_str"

    if [[ ! -d "$SCAN_DIRECTORY" ]]; then
        log_error "Scan directory does not exist: $SCAN_DIRECTORY"
        exit 1
    fi

    local need_packages=false
    [[ "$SCAN_CLAMAV" == true ]] && ! command_exists clamscan && need_packages=true
    [[ "$SCAN_MALDET" == true ]] && ! command_exists maldet && need_packages=true
    [[ "$need_packages" == true ]] && prepare_system

    if [[ "$SCAN_CLAMAV" == true ]]; then
        log_info "Phase 1: ClamAV"
        install_clamav || exit 1
    fi

    if [[ "$SCAN_MALDET" == true ]]; then
        log_info "Phase 2: Maldet"
        if ! install_maldet; then
            if [[ "$SCAN_CLAMAV" == false ]]; then
                log_error "Maldet is the only requested scanner and could not be installed"
                exit 1
            fi
            log_warning "Continuing with ClamAV-only scanning"
            SCAN_MALDET=false
        fi
    fi

    log_info "Phase 3: Malware Scanning"
    if ! perform_scan "$SCAN_DIRECTORY"; then
        log_error "The malware scan did not complete successfully"
        review_findings
        exit 1
    fi

    review_findings

    log_success "Malware Scan Complete"
    log_info "All logs saved to: $LOG_DIR"
}

main "$@"

