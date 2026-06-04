"""
main.py — Entry point for the Hybrid IDS.

All configuration is read from the .env file (see .env.example).
Do NOT hardcode tokens or IPs here.

Run:
    sudo python main.py
"""
import sys
import logging

from ids import IntrusionDetectionSystem

logger = logging.getLogger(__name__)


def main() -> None:
    print("=" * 50)
    print("  Hybrid IDS — Final Year Project")
    print("  ML Model  : IsolationForest (CIC-IDS2017)")
    print("  Detection : Signature + Anomaly")
    print("=" * 50)

    ids = IntrusionDetectionSystem()

    try:
        ids.start()
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        ids.stop()
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        ids.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
