from __future__ import annotations

import importlib.util
import unittest

from cloakscan.config import load_scan_config
from cloakscan.models import TargetSpec, ViewSnapshot

_HAS_BS4 = importlib.util.find_spec("bs4") is not None


@unittest.skipUnless(_HAS_BS4, "beautifulsoup4 not installed")
class DetectorTests(unittest.TestCase):
    def test_detects_bot_mismatch_and_keyword_signal(self) -> None:
        from cloakscan.detect import detect_signals

        config = load_scan_config("balanced", config_path=None)
        target = TargetSpec(raw="example.com", normalized_url="https://example.com/")
        views = {
            "browser": ViewSnapshot(
                profile="browser",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body><h1>Welcome to our normal page</h1></body></html>",
            ),
            "bot": ViewSnapshot(
                profile="bot",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body>Casino jackpot betting sportsbook poker now</body></html>",
            ),
        }
        signals = detect_signals(target=target, views=views, config=config)
        codes = {signal.code for signal in signals}
        self.assertIn("bot_human_mismatch", codes)
        self.assertIn("casino_keywords", codes)
        mismatch_signal = next(signal for signal in signals if signal.code == "bot_human_mismatch")
        keyword_signal = next(signal for signal in signals if signal.code == "casino_keywords")
        self.assertTrue(any("bot-only text sample:" in detail for detail in mismatch_signal.details))
        self.assertTrue(any("matched keywords:" in detail for detail in keyword_signal.details))

    def test_detects_japanese_signal_when_conditions_match(self) -> None:
        from cloakscan.detect import detect_signals

        config = load_scan_config("balanced", config_path=None)
        target = TargetSpec(raw="example.com", normalized_url="https://example.com/")
        views = {
            "browser": ViewSnapshot(
                profile="browser",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body>Normal English page for users</body></html>",
            ),
            "bot": ViewSnapshot(
                profile="bot",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html=(
                    "<html><body>激安 偽ブランド ブランドコピー オンラインカジノ "
                    "アダルト 医薬品 激安 偽ブランド ブランドコピー</body></html>"
                ),
            ),
        }
        signals = detect_signals(target=target, views=views, config=config)
        codes = {signal.code for signal in signals}
        self.assertIn("japanese_spam_signal", codes)

    def test_outbound_link_signal_includes_domains_and_links(self) -> None:
        from cloakscan.detect import detect_signals

        config = load_scan_config("balanced", config_path=None)
        config.thresholds.outbound_link_delta_min = 2
        config.thresholds.external_domain_delta_min = 2

        target = TargetSpec(raw="example.com", normalized_url="https://example.com/")
        views = {
            "browser": ViewSnapshot(
                profile="browser",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body><a href='https://example.com/about'>About</a></body></html>",
            ),
            "headless": ViewSnapshot(
                profile="headless",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html=(
                    "<html><body>"
                    "<a href='https://spam-one.example/path'>One</a>"
                    "<a href='https://spam-two.example/path'>Two</a>"
                    "<a href='https://spam-three.example/path'>Three</a>"
                    "</body></html>"
                ),
            ),
        }

        signals = detect_signals(target=target, views=views, config=config)
        link_signal = next(signal for signal in signals if signal.code == "outbound_link_injection")
        self.assertTrue(any("new external domains" in detail for detail in link_signal.details))
        self.assertTrue(any("sample added links" in detail for detail in link_signal.details))


    def test_detects_root_to_subpath_bot_redirect(self) -> None:
        from cloakscan.detect import detect_signals

        config = load_scan_config("balanced", config_path=None)
        target = TargetSpec(raw="example.com", normalized_url="https://example.com/")
        views = {
            "browser": ViewSnapshot(
                profile="browser",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body>Normal page</body></html>",
                redirect_chain=["https://example.com/"],
            ),
            "bot": ViewSnapshot(
                profile="bot",
                requested_url="https://example.com/",
                final_url="https://example.com/spam/",
                status_code=200,
                html="<html><body>Spam landing page</body></html>",
                redirect_chain=["https://example.com/", "https://example.com/spam/"],
            ),
        }

        signals = detect_signals(target=target, views=views, config=config)
        redirect_signal = next(signal for signal in signals if signal.code == "sneaky_redirect")

        self.assertIn("final URL diff", " ".join(redirect_signal.details))
        self.assertTrue(any("bot redirect chain:" in detail for detail in redirect_signal.details))

    def test_detects_bot_only_redirect_chain_with_same_final_url(self) -> None:
        from cloakscan.detect import detect_signals

        config = load_scan_config("balanced", config_path=None)
        target = TargetSpec(raw="example.com", normalized_url="https://example.com/")
        views = {
            "browser": ViewSnapshot(
                profile="browser",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body>Normal page</body></html>",
                redirect_chain=["https://example.com/"],
            ),
            "bot": ViewSnapshot(
                profile="bot",
                requested_url="https://example.com/",
                final_url="https://example.com/",
                status_code=200,
                html="<html><body>Normal page</body></html>",
                redirect_chain=[
                    "https://example.com/",
                    "https://example.com/gate/",
                    "https://example.com/",
                ],
            ),
        }

        signals = detect_signals(target=target, views=views, config=config)
        redirect_signal = next(signal for signal in signals if signal.code == "sneaky_redirect")

        self.assertFalse(any("final URL diff" in detail for detail in redirect_signal.details))
        self.assertTrue(any("browser redirect chain:" in detail for detail in redirect_signal.details))
        self.assertTrue(any("bot redirect chain:" in detail for detail in redirect_signal.details))


if __name__ == "__main__":
    unittest.main()
