"""Unit tests for private-repo authentication: _build_clone_url."""
from __future__ import annotations
import pytest
from argus.cli import _build_clone_url


class TestBuildCloneUrl:
    def test_no_token_returns_original(self):
        url = "https://github.com/owner/repo"
        assert _build_clone_url(url, None) == url

    def test_empty_token_returns_original(self):
        url = "https://github.com/owner/repo"
        assert _build_clone_url(url, "") == url

    def test_local_path_unchanged(self):
        path = "/tmp/some-repo"
        assert _build_clone_url(path, "mytoken") == path

    def test_ssh_url_unchanged(self):
        url = "git@github.com:owner/repo.git"
        assert _build_clone_url(url, "mytoken") == url

    def test_github_token_uses_x_access_token(self):
        url = "https://github.com/owner/private-repo"
        result = _build_clone_url(url, "ghp_abc123")
        assert result == "https://x-access-token:ghp_abc123@github.com/owner/private-repo"

    def test_github_url_with_dot_git_suffix(self):
        url = "https://github.com/owner/private-repo.git"
        result = _build_clone_url(url, "ghp_abc123")
        assert result == "https://x-access-token:ghp_abc123@github.com/owner/private-repo.git"

    def test_gitlab_token_uses_oauth2(self):
        url = "https://gitlab.com/group/project"
        result = _build_clone_url(url, "glpat-xyz789")
        assert result == "https://oauth2:glpat-xyz789@gitlab.com/group/project"

    def test_self_hosted_gitlab_token(self):
        url = "https://git.internal.company.com/team/repo"
        result = _build_clone_url(url, "mytoken")
        # Generic HTTPS: token injected directly
        assert result == "https://mytoken@git.internal.company.com/team/repo"

    def test_bitbucket_token_uses_x_token_auth(self):
        url = "https://bitbucket.org/team/repo"
        result = _build_clone_url(url, "ATBB_xyz")
        assert result == "https://x-token-auth:ATBB_xyz@bitbucket.org/team/repo"

    def test_token_only_inserted_once(self):
        url = "https://github.com/owner/repo"
        result = _build_clone_url(url, "tok")
        assert result.count("@") == 1
        assert result.startswith("https://x-access-token:tok@")

    def test_original_url_not_mutated(self):
        url = "https://github.com/owner/repo"
        _build_clone_url(url, "tok")
        assert url == "https://github.com/owner/repo"
