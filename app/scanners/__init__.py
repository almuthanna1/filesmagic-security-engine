from app.scanners.base import Scanner

# Scanners run by POST /scan. Empty until real scanners are implemented,
# which makes every scan return UNABLE_TO_SCAN.
SCANNERS: list[Scanner] = []
