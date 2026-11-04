"""R11-A 网络边界离线契约测试；不在宿主执行特权网络操作。"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from foam.guard import network, network_helper
from foam.guard.network import (
    BoundaryError,
    ExecutionUnsupportedError,
    NetworkBoundary,
    NetworkPolicy,
)
from foam.guard.scope import parse_scope


class FakeTransport:
    """通过公开 client 接口驱动代际，不创建真实 namespace。"""

    instances: list[FakeTransport] = []
    create_error: Exception | None = None
    apply_error: Exception | None = None
    response_patch: dict = {}

    def __init__(self, boundary_id, state_dir, workdir, *, recover=False):
        self.boundary_id = boundary_id
        self.state_dir = state_dir
        self.workdir = workdir
        self.recover = recover
        self.requests = []
        self.close_calls = 0
        self.epoch = 0
        self.init_pid = 2000
        self.closed = False
        self.fds = []
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.create_error = None
        cls.apply_error = None
        cls.response_patch = {}

    def request(self, payload, *, fd_count=0):
        self.requests.append(payload)
        if payload["op"] == "create" and self.create_error is not None:
            raise self.create_error
        if payload["op"] == "apply" and self.apply_error is not None:
            raise self.apply_error
        if payload["op"] in {"create", "apply"}:
            self.epoch += 1
            self.init_pid += 1
            response = {
                "ok": True,
                "boundary_id": self.boundary_id,
                "epoch": self.epoch,
                "init_pid": self.init_pid,
                "init_start": "1234",
                "helper_pid": 4100,
                "netns": f"fn{self.boundary_id[-12:]}",
                "scope_digest": payload["policy"]["digest"],
                "capabilities": {
                    "helper": ["setgid", "setuid", "kill", "net_admin", "sys_admin"],
                    "tool": [],
                    "no_new_privs": True,
                },
            }
            response.update(self.response_patch)
            fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(fd_count)]
            self.fds.extend(fds)
            return response, fds
        if payload["op"] == "retire":
            return {"ok": True}, []
        if payload["op"] == "close":
            self.closed = True
            return {
                "ok": True,
                "cleanup_status": "clean",
                "remaining_resources": [],
                "errors": [],
            }, []
        if payload["op"] == "recover":
            return {
                "ok": True,
                "cleanup_status": "clean",
                "remaining_resources": [],
                "errors": [],
            }, []
        return {"ok": True, "epoch": self.epoch}, []

    def close(self):
        self.close_calls += 1


@pytest.fixture(autouse=True)
def fake_transport(monkeypatch):
    FakeTransport.reset()
    monkeypatch.setattr(network, "_HelperTransport", FakeTransport)
    monkeypatch.setattr(network, "_require_supported", lambda: None)
    monkeypatch.setattr(network, "_private_workdir", network._private_directory)
    monkeypatch.setattr(network_helper, "_process_start", lambda pid: "1234")


def make_boundary(tmp_path, scope_text="192.0.2.0/24\n2001:db8::/32"):
    return NetworkBoundary.create(
        parse_scope(scope_text),
        dns="192.0.2.53",
        digest="sha256:TESTONLY",
        state_root=tmp_path / "state",
        work_root=tmp_path / "work",
    )


# ---------------------------------------------------------------- policy


def test_policy_accepts_only_normalized_cidrs_and_dns():
    policy = NetworkPolicy.from_scope(
        parse_scope("192.0.2.1\n2001:db8::/32"),
        dns="2001:db8::53",
        digest="abc",
    )
    assert [str(item) for item in policy.cidrs] == [
        "192.0.2.1/32",
        "2001:db8::/32",
    ]
    assert str(policy.dns) == "2001:db8::53"
    assert policy.digest == "abc"


@pytest.mark.parametrize(
    "scope_text",
    [
        "target.example.com",
        "*.example.com",
        "https://192.0.2.1/private",
        "192.0.2.0/24\ntarget.example.com",
        "192.0.2.0/24\n*.example.com",
        "192.0.2.0/24\nhttps://192.0.2.1/",
    ],
)
def test_policy_rejects_unsupported_and_mixed_scope_as_a_whole(scope_text):
    with pytest.raises(BoundaryError, match="仅支持 CIDR"):
        NetworkPolicy.from_scope(parse_scope(scope_text))


def test_empty_policy_is_valid_and_denies_all_destinations():
    policy = NetworkPolicy.from_scope(parse_scope(""))
    assert policy.cidrs == ()
    rules = network_helper.render_nft_rules(
        policy,
        table="fntest",
        interface="vtest",
        ipv4="10.255.0.2",
        ipv6="fd11::2",
    )
    assert "meta l4proto" not in rules
    assert "echo-request accept" not in rules
    assert 'iifname "vtest" ip saddr 10.255.0.2 drop' in rules
    assert 'iifname "vtest" ip6 saddr fd11::2 drop' in rules


@pytest.mark.parametrize("dns", [None, "192.0.2.53", "2001:db8::53"])
def test_dns_must_be_an_address_inside_some_authorized_cidr(dns):
    if dns is None or dns == "192.0.2.53":
        policy = NetworkPolicy.from_scope(parse_scope("192.0.2.0/24"), dns=dns)
        assert policy.dns is None or str(policy.dns) == dns
    else:
        with pytest.raises(BoundaryError, match="DNS"):
            NetworkPolicy.from_scope(parse_scope("192.0.2.0/24"), dns=dns)


@pytest.mark.parametrize("dns", ["dns.example.com", "198.51.100.53", "not-an-ip"])
def test_policy_rejects_unauthorized_dns(dns):
    with pytest.raises(BoundaryError, match="DNS"):
        NetworkPolicy.from_scope(parse_scope("192.0.2.0/24"), dns=dns)


def test_dns_is_rejected_for_empty_scope():
    with pytest.raises(BoundaryError, match="DNS"):
        NetworkPolicy.from_scope(parse_scope(""), dns="192.0.2.53")


# ------------------------------------------------------------- strict JSON


@pytest.mark.parametrize(
    "op", ["create", "retire", "apply", "close", "status", "recover"]
)
def test_protocol_has_only_six_structured_operations(op):
    payload = {"op": op}
    if op in {"create", "apply"}:
        payload["policy"] = {"cidrs": [], "dns": None, "digest": ""}
    decoded = network_helper.decode_request(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    assert decoded["op"] == op


@pytest.mark.parametrize(
    "payload",
    [
        {"op": "shell", "command": "id"},
        {"op": "status", "nft": "flush ruleset"},
        {"op": "close", "unknown": True},
        {"op": "create"},
        {"op": "apply", "policy": {"cidrs": [], "dns": None}},
        {"op": "retire", "argv": ["kill", "-9", "1"]},
        {"op": 1},
        [],
    ],
)
def test_protocol_rejects_unknown_commands_fields_and_shapes(payload):
    with pytest.raises(network_helper.ProtocolError):
        network_helper.decode_request(json.dumps(payload).encode())


def test_protocol_rejects_duplicate_keys_bad_json_and_oversized_input():
    for raw in (
        b'{"op":"status","op":"close"}',
        b'{"op":"status"',
        b'{"op":"status","x":NaN}',
        b" " * (network_helper.MAX_MESSAGE_SIZE + 1),
    ):
        with pytest.raises(network_helper.ProtocolError):
            network_helper.decode_request(raw)


# ----------------------------------------------------- privilege and nft


def capability_status(mask):
    value = f"{mask:016x}"
    return {
        "CapInh": "0000000000000000",
        "CapPrm": value,
        "CapEff": value,
        "CapBnd": value,
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }


def test_helper_requires_exact_five_capability_sets_securebits_and_nnp():
    mask = network_helper.required_capability_mask()
    report = network_helper.verify_security_status(
        capability_status(mask),
        securebits=network_helper.REQUIRED_SECUREBITS,
    )
    assert report["capabilities"] == [
        "setgid",
        "kill",
        "setuid",
        "net_admin",
        "sys_admin",
    ]
    assert report["no_new_privs"] is True


@pytest.mark.parametrize("field", ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])
def test_helper_rejects_capability_leak(field):
    mask = network_helper.required_capability_mask()
    status = capability_status(mask)
    status[field] = f"{mask | (1 << 2):016x}"
    with pytest.raises(BoundaryError):
        network_helper.verify_security_status(
            status, securebits=network_helper.REQUIRED_SECUREBITS
        )


def test_helper_rejects_missing_nnp_or_securebits():
    mask = network_helper.required_capability_mask()
    with pytest.raises(BoundaryError, match="NoNewPrivs"):
        network_helper.verify_security_status(
            {**capability_status(mask), "NoNewPrivs": "0"},
            securebits=network_helper.REQUIRED_SECUREBITS,
        )
    with pytest.raises(BoundaryError, match="securebits"):
        network_helper.verify_security_status(capability_status(mask), securebits=0)


def test_nft_defaults_to_accept_for_bystanders_and_filters_only_run():
    policy = NetworkPolicy.from_scope(
        parse_scope("192.0.2.0/24\n2001:db8::/32"), dns="192.0.2.53"
    )
    rules = network_helper.render_nft_rules(
        policy,
        table="fnrun",
        interface="vrun",
        ipv4="10.255.0.2",
        ipv6="fd11::2",
    )
    assert "type filter hook forward priority filter; policy accept;" in rules
    assert "type filter hook input priority filter; policy accept;" in rules
    assert "policy drop" not in rules
    assert "flush ruleset" not in rules
    assert 'iifname "vrun" ip saddr 10.255.0.2 ip daddr 192.0.2.0/24' in rules
    assert 'iifname "vrun" ip6 saddr fd11::2 ip6 daddr 2001:db8::/32' in rules
    assert "ip6 daddr 2001:db8::/32 meta l4proto { tcp, udp } accept" in rules
    assert "nd-neighbor-solicit" in rules
    assert "nd-neighbor-advert" in rules
    assert "masquerade" in rules
    assert (
        'iifname "vrun" ip saddr 10.255.0.2 oifname != "vrun" masquerade' in rules
    )
    assert (
        'iifname "vrun" ip6 saddr fd11::2 oifname != "vrun" masquerade' in rules
    )
    assert ' ip saddr fd11::2 ' not in rules


def test_nft_apply_replaces_only_the_per_run_table_atomically():
    rules = network_helper.render_nft_rules(
        NetworkPolicy.from_scope(parse_scope("")),
        table="fnrun",
        interface="vrun",
        ipv4="10.255.0.2",
        ipv6="fd11::2",
        replace=True,
    )
    assert rules.startswith("delete table inet fnrun\ntable inet fnrun {")
    assert "flush ruleset" not in rules
    assert "delete table inet other" not in rules


class AbsentRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        return SimpleNamespace(returncode=1, stdout="", stderr="not found")


def make_helper(tmp_path, runner=None):
    state = tmp_path / "state" / "fb0123456789ab"
    work = tmp_path / "work" / "fb0123456789ab"
    state.mkdir(parents=True)
    work.mkdir(parents=True)
    return network_helper.BoundaryHelper(
        "fb0123456789ab", state, work, runner=runner or AbsentRunner()
    )


def test_cleanup_never_deletes_resources_not_created_by_helper(tmp_path):
    runner = AbsentRunner()
    helper = make_helper(tmp_path, runner)
    result = helper.cleanup()
    assert result["cleanup_status"] == "clean"
    assert not any(
        argv[:3] in (["nft", "delete", "table"], ["ip", "netns", "del"])
        or argv[:3] == ["ip", "link", "del"]
        for argv in runner.calls
    )


def test_stop_generation_failure_preserves_recoverable_identity(tmp_path):
    helper = make_helper(tmp_path)
    generation = SimpleNamespace(
        close_fds=lambda: pytest.fail("失败代际不得提前关闭 FD"),
        launcher=SimpleNamespace(wait=lambda timeout: None),
    )
    helper.generation = generation
    writes = []
    monkeypatch = pytest.MonkeyPatch()
    def fail_signal(current):
        raise BoundaryError("injected")

    monkeypatch.setattr(helper, "_signal_generation", fail_signal)
    monkeypatch.setattr(helper, "_write_manifest", writes.append)
    try:
        with pytest.raises(BoundaryError, match="injected"):
            helper._stop_generation()
        assert helper.generation is generation
        assert writes == []
    finally:
        monkeypatch.undo()


def test_resolver_cleanup_failure_is_explicit(tmp_path, monkeypatch):
    helper = make_helper(tmp_path)
    helper._resolver_created = True
    helper._resolver_dir_created = True
    original_unlink = network_helper.Path.unlink
    resolver = network_helper.Path("/etc/netns") / helper.config.netns / "resolv.conf"

    def fail_resolver(path, *args, **kwargs):
        if path == resolver:
            raise OSError("injected resolver cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(network_helper.Path, "unlink", fail_resolver)
    result = helper.cleanup()
    assert result["cleanup_status"] == "failed"
    assert "injected resolver cleanup failure" in result["errors"][-1]


# ---------------------------------------------------------- manifest trust


def manifest_data(boundary_id="fb0123456789ab"):
    config = network_helper.resource_config(boundary_id)
    return {
        "version": 1,
        "boundary_id": boundary_id,
        **config.manifest_names,
        "helper_pid": 4100,
        "helper_start": "1234",
        "generation": None,
    }


def test_manifest_requires_exact_root_owned_per_run_identity(tmp_path):
    path = tmp_path / "manifest.json"
    expected = manifest_data()
    path.write_text(json.dumps(expected), encoding="utf-8")
    path.chmod(0o600)
    loaded = network_helper.read_manifest(
        path,
        expected_boundary_id=expected["boundary_id"],
        owner_uid=os.getuid(),
    )
    assert loaded == expected


@pytest.mark.parametrize(
    "change", [{"netns": "other"}, {"boundary_id": "fbabcdefabcdef"}]
)
def test_manifest_rejects_unknown_resource_ownership(tmp_path, change):
    path = tmp_path / "manifest.json"
    data = {**manifest_data(), **change}
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(BoundaryError, match="manifest"):
        network_helper.read_manifest(
            path,
            expected_boundary_id="fb0123456789ab",
            owner_uid=os.getuid(),
        )


def test_manifest_rejects_wrong_owner_or_permissions(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest_data()), encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(BoundaryError, match="manifest"):
        network_helper.read_manifest(
            path,
            expected_boundary_id="fb0123456789ab",
            owner_uid=os.getuid(),
        )
    path.chmod(0o600)
    with pytest.raises(BoundaryError, match="manifest"):
        network_helper.read_manifest(
            path,
            expected_boundary_id="fb0123456789ab",
            owner_uid=os.getuid() + 1,
        )


# ----------------------------------------------------------- public client


def test_create_exposes_generation_fds_workdir_and_capabilities(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        assert boundary.boundary_id.startswith("fb")
        assert boundary.epoch == 1
        assert boundary.init_pid == 2001
        assert boundary.helper_pid == 4100
        assert boundary.pid_namespace_fd >= 0
        assert boundary.mount_namespace_fd >= 0
        assert boundary.mount_namespace_fd != boundary.pid_namespace_fd
        assert boundary.workdir == tmp_path / "work" / boundary.boundary_id
        assert boundary.workdir.is_dir()
        assert boundary.capabilities()["no_new_privs"] is True
        assert FakeTransport.instances[0].requests[0]["op"] == "create"
    finally:
        boundary.aclose()


def test_tool_adapter_uses_fixed_namespace_and_nonroot_wrapper(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        argv = boundary.tool_argv(["bash", "-c", "id"])
        assert argv[0] == "nsenter"
        assert argv[argv.index("ip") : argv.index("ip") + 4] == [
            "ip",
            "netns",
            "exec",
            boundary._netns,
        ]
        assert f"--mount=/proc/self/fd/{boundary.mount_namespace_fd}" in argv
        assert f"--pid=/proc/self/fd/{boundary.pid_namespace_fd}" in argv
        assert "-F" not in argv and "--no-fork" not in argv
        assert "setpriv" in argv
        assert "--reuid=65534" in argv
        assert "--regid=65534" in argv
        assert "--bounding-set=-all" in argv
        assert "--no-new-privs" in argv
        assert argv[-3:] == ["bash", "-c", "id"]
        spawned = boundary.spawn_kwargs()
        assert boundary.pid_namespace_fd in spawned["pass_fds"]
        assert boundary.mount_namespace_fd in spawned["pass_fds"]
        assert spawned["cwd"] == str(boundary.workdir)
    finally:
        boundary.aclose()


def test_tool_env_is_a_fixed_secret_and_proxy_free_allowlist(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        env = boundary.tool_env("xterm-256color")
        assert set(env) == {
            "PATH",
            "HOME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "USER",
            "LOGNAME",
            "TERM",
        }
        assert env["TERM"] == "xterm-256color"
        assert env["HOME"] == str(boundary.workdir)
        assert not (
            {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FOAM_LLM_API_KEY"} & set(env)
        )
        assert "TERM" not in boundary.tool_env()
    finally:
        boundary.aclose()


def test_retire_then_apply_replaces_fds_and_increments_epoch(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        boundary.retire_generation()
        with pytest.raises(BoundaryError, match="活动代际"):
            boundary.tool_argv(["id"])
        boundary.apply_scope(parse_scope("198.51.100.0/24"), digest="next")
        assert boundary.epoch == 2
        assert boundary.init_pid == 2002
        assert os.fstat(boundary.pid_namespace_fd).st_mode
        assert os.fstat(boundary.mount_namespace_fd).st_mode
        assert [request["op"] for request in FakeTransport.instances[0].requests] == [
            "create",
            "retire",
            "apply",
        ]
    finally:
        boundary.aclose()


def test_create_failure_never_returns_degraded_boundary(tmp_path):
    FakeTransport.create_error = BoundaryError("injected setup failure")
    with pytest.raises(BoundaryError, match="injected setup failure"):
        make_boundary(tmp_path)
    transport = FakeTransport.instances[0]
    assert transport.close_calls == 1
    assert list((tmp_path / "state").iterdir()) == []
    assert list((tmp_path / "work").iterdir()) == []


def test_create_permission_failure_is_unsupported_and_cleans(tmp_path, monkeypatch):
    def deny_chown(_path):
        raise PermissionError("TESTONLY chown denied")

    monkeypatch.setattr(network, "_private_workdir", deny_chown)
    with pytest.raises(ExecutionUnsupportedError, match="权限不足"):
        make_boundary(tmp_path)
    assert list((tmp_path / "state").iterdir()) == []
    assert list((tmp_path / "work").iterdir()) == []
    assert FakeTransport.instances == []


@pytest.mark.parametrize(
    "patch", [{"scope_digest": "sha256:WRONG"}, {"helper_pid": 0}]
)
def test_create_response_validation_closes_fds_and_directories(tmp_path, patch):
    FakeTransport.response_patch = patch
    with pytest.raises(BoundaryError):
        make_boundary(tmp_path)
    transport = FakeTransport.instances[0]
    assert len(transport.fds) == 2
    for fd in transport.fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert transport.close_calls == 1
    assert list((tmp_path / "state").iterdir()) == []
    assert list((tmp_path / "work").iterdir()) == []


@pytest.mark.parametrize(
    "patch", [{"scope_digest": "sha256:WRONG"}, {"helper_pid": 0}]
)
def test_apply_response_validation_closes_new_fds_and_fails_closed(tmp_path, patch):
    boundary = make_boundary(tmp_path)
    transport = FakeTransport.instances[0]
    old_fds = transport.fds[:]
    try:
        FakeTransport.response_patch = patch
        with pytest.raises(BoundaryError):
            boundary.apply_scope(parse_scope("198.51.100.0/24"), digest="next")
        assert boundary.epoch == 1
        with pytest.raises(BoundaryError, match="失败"):
            boundary.tool_argv(["id"])
        assert len(transport.fds) == 4
        for fd in transport.fds[2:]:
            with pytest.raises(OSError):
                os.fstat(fd)
        for fd in old_fds:
            assert os.fstat(fd).st_mode
    finally:
        boundary.aclose()
    for fd in old_fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_apply_failure_keeps_epoch_and_fails_closed(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        FakeTransport.apply_error = BoundaryError("injected nft failure")
        with pytest.raises(BoundaryError, match="injected nft failure"):
            boundary.apply_scope(parse_scope("198.51.100.0/24"))
        assert boundary.epoch == 1
        with pytest.raises(BoundaryError, match="失败"):
            boundary.tool_argv(["id"])
    finally:
        result = boundary.aclose()
        assert result["cleanup_status"] == "clean"


def test_invalid_apply_scope_also_fails_closed(tmp_path):
    boundary = make_boundary(tmp_path)
    try:
        with pytest.raises(BoundaryError, match="仅支持 CIDR"):
            boundary.apply_scope(parse_scope("target.example.com"))
        with pytest.raises(BoundaryError, match="失败"):
            boundary.tool_argv(["id"])
        assert FakeTransport.instances[0].requests[-1]["op"] == "create"
    finally:
        boundary.aclose()


def test_close_is_idempotent_and_reports_cleanup(tmp_path):
    boundary = make_boundary(tmp_path)
    first = boundary.aclose()
    second = boundary.aclose()
    assert first == second
    assert first == {
        "cleanup_status": "clean",
        "remaining_resources": [],
        "errors": [],
    }
    assert not (tmp_path / "work" / boundary.boundary_id).exists()
    assert not (tmp_path / "state" / boundary.boundary_id).exists()
    transport = FakeTransport.instances[0]
    assert [request["op"] for request in transport.requests].count("close") == 1
    assert transport.close_calls == 1


def test_recover_stale_empty_root_is_bounded_and_honest(tmp_path):
    assert network.recover_stale(state_root=tmp_path / "state") == []


def test_recover_cleaned_marker_and_reject_unknown_directory(
    tmp_path, monkeypatch
):
    state_root = tmp_path / "state"
    cleaned_id = "fb0123456789ab"
    unknown_id = "fbabcdefabcdef"
    cleaned_dir = state_root / cleaned_id
    unknown_dir = state_root / unknown_id
    cleaned_dir.mkdir(parents=True, mode=0o700)
    unknown_dir.mkdir(mode=0o700)
    cleaned_dir.chmod(0o700)
    unknown_dir.chmod(0o700)
    network_helper.write_manifest(
        cleaned_dir / network_helper._CLEANED_MANIFEST,
        manifest_data(cleaned_id),
    )
    original_read = network_helper.read_manifest

    def read_owned(path, *, expected_boundary_id):
        return original_read(
            path, expected_boundary_id=expected_boundary_id, owner_uid=os.getuid()
        )

    monkeypatch.setattr(network_helper, "read_manifest", read_owned)
    monkeypatch.setattr(network, "_process_is_active", lambda _pid, _start: False)
    results = network.recover_stale(
        state_root=state_root, work_root=tmp_path / "work"
    )
    by_id = {item["boundary_id"]: item for item in results}
    assert by_id[cleaned_id]["cleanup_status"] == "clean"
    assert by_id[unknown_id]["cleanup_status"] == "rejected"
    assert not cleaned_dir.exists()
    assert unknown_dir.is_dir()
    assert FakeTransport.instances == []
    with pytest.raises(BoundaryError, match="拒绝新 run"):
        NetworkBoundary.create(
            parse_scope(""), state_root=state_root, work_root=tmp_path / "work"
        )
    assert unknown_dir.is_dir()
    assert FakeTransport.instances == []


@pytest.mark.parametrize(
    ("platform", "euid"),
    [("darwin", 0), ("linux", 1000)],
)
def test_protected_mode_requires_linux_root_without_sudo(
    monkeypatch, tmp_path, platform, euid
):
    monkeypatch.setattr(network, "_require_supported", network_helper.require_supported)
    monkeypatch.setattr(network_helper.sys, "platform", platform)
    monkeypatch.setattr(network_helper.os, "geteuid", lambda: euid)
    with pytest.raises(ExecutionUnsupportedError, match="Linux.*root"):
        NetworkBoundary.create(
            parse_scope(""), state_root=tmp_path / "s", work_root=tmp_path / "w"
        )
