from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

from team_protocol.cli import build_parser, main


class CliCutoverTests(unittest.TestCase):
    def _commands(self) -> dict[str, argparse.ArgumentParser]:
        parser = build_parser()
        action = next(
            item
            for item in parser._actions
            if isinstance(item, argparse._SubParsersAction)
        )
        return dict(action.choices)

    def test_legacy_runtime_commands_and_parameters_are_absent(self) -> None:
        parser = build_parser()
        commands = self._commands()

        self.assertNotIn("workflow", commands)
        self.assertNotIn("login-otp", commands)
        self.assertNotIn("tk-gui", commands)
        self.assertTrue(
            {
                "analyze",
                "convert",
                "push",
                "invite",
                "leave",
                "create-token",
                "refresh-session",
                "web",
                "gui",
            }.issubset(commands)
        )

        help_text = "\n".join(
            [parser.format_help(), *(command.format_help() for command in commands.values())]
        )
        self.assertNotIn("--config", help_text)
        self.assertNotIn("--mail-account-file", help_text)
        self.assertNotIn("tk-gui", help_text)

    def test_web_routes_only_server_options(self) -> None:
        with patch("team_protocol.web_console.serve_web_console", return_value=17) as serve:
            result = main(["web", "--port", "9012", "--no-browser"])

        self.assertEqual(result, 17)
        serve.assert_called_once_with(port=9012, open_browser=False)

    def test_gui_is_web_compatibility_alias(self) -> None:
        with patch("team_protocol.web_console.serve_web_console", return_value=23) as serve:
            result = main(["gui"])

        self.assertEqual(result, 23)
        serve.assert_called_once_with(port=8765, open_browser=True)


if __name__ == "__main__":
    unittest.main()
