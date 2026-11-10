from app.config import _parse_env_line


def test_env_parser_handles_comments_and_quotes():
    assert _parse_env_line("API_KEY=abc   # require X-API-Key") == ("API_KEY", "abc")
    assert _parse_env_line("API_KEY=            # empty with comment") == ("API_KEY", "")
    assert _parse_env_line('NAME="a # not a comment"') == ("NAME", "a # not a comment")
    assert _parse_env_line("DLP_WRAPPED_KEY=Q2lRQS9+abc==") == ("DLP_WRAPPED_KEY", "Q2lRQS9+abc==")
    assert _parse_env_line("URL=https://x/#frag") == ("URL", "https://x/#frag")
    assert _parse_env_line("# GEMINI_MODEL=x") is None
    assert _parse_env_line("") is None
