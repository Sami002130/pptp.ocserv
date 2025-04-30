#!/usr/bin/env bash

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] This script must be run as root." >&2
  exit 1
fi

# Set PATH
export PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"

# URLs for option scripts (raw content)
URL_INSTALL="https://raw.githubusercontent.com/Sami002130/pptp.ocserv/main/c.sh"
URL_MANAGE="https://raw.githubusercontent.com/Sami002130/pptp.ocserv/main/a.sh"
URL_UNINSTALL="https://raw.githubusercontent.com/Sami002130/pptp.ocserv/main/rc.sh"

# Temporary download directory
TMP_DIR="/tmp/pptp_menu"
mkdir -p "$TMP_DIR"

while true; do
  clear
  echo "===== Main Menu ====="
  echo "1) install"
  echo "2) manage"
  echo "3) uninstall"
  echo "0) Exit"
  echo "====================="
  read -rp "Select an option: " choice

  case "$choice" in
    1)
      curl -sSL "$URL_INSTALL" -o "$TMP_DIR/c.sh" && chmod +x "$TMP_DIR/c.sh" && bash "$TMP_DIR/c.sh"
      read -rp "Press any key to return to menu..." dummy
      ;;
    2)
      curl -sSL "$URL_MANAGE" -o "$TMP_DIR/a.sh" && chmod +x "$TMP_DIR/a.sh" && bash "$TMP_DIR/a.sh"
      read -rp "Press any key to return to menu..." dummy
      ;;
    3)
      curl -sSL "$URL_UNINSTALL" -o "$TMP_DIR/rc.sh" && chmod +x "$TMP_DIR/rc.sh" && bash "$TMP_DIR/rc.sh"
      read -rp "Press any key to return to menu..." dummy
      ;;
    0)
      exit 0
      ;;
    *)
      echo "[WARN] Invalid selection. Please choose 0-3."
      read -rp "Press any key to try again..." dummy
      ;;
  esac
done
