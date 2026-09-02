from __future__ import annotations

import ipaddress
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import byte_digest, canonical_digest, load_json, load_json_bytes, secure_read
from .crypto import b64url_decode, signature_payload, verify
from .errors import ConformanceError
from .schema import closed, require_digest, require_key_id, require_object, require_time

ENVELOPE_SCHEMA = "harness.planeon.ai/live-campaign-execution-envelope/v1alpha1"
CAPACITY_SCHEMA = "harness.planeon.ai/live-capacity-authorization/v1alpha1"
ENVELOPE_DOMAIN = "planeon.harness-live-execution-envelope/v1alpha1"
CAPACITY_DOMAIN = "planeon.harness-live-capacity-authorization/v1alpha1"
TREE_DOMAIN = "planeon.harness-live-tree/v1alpha1"
COMMAND_DOMAIN = "planeon.harness-live-command-set/v1alpha1"
PINNED_ROOT_PUBLIC_KEY_SHA256 = "sha256:6b22a99cab70c60b7cc345962ae220e32b2dbc89c72b419c79a9c92ec5f6c012"
FIXED_RELEASE_TRUST = Path("/etc/planeon/trust/release-trust-bundle.json")
FIXED_TENANT_TRUST = Path("/etc/planeon/trust/tenant-trust-bundle.json")
FIXED_MANIFEST = Path("/etc/planeon/harness-live-runner-manifest.json")
FIXED_MANIFEST_SIGNATURE = Path("/etc/planeon/harness-live-runner-manifest.json.sig")
FIXED_MANIFEST_PUBLIC = Path("/etc/planeon/harness-live-runner-manifest.pub")
EXPECTED_LAUNCHER = Path("/opt/planeon/bin/harness-live-campaign-launch")

ENVELOPE_FIELDS = {
    "schemaVersion", "packetId", "packetFileReference", "packetDigest", "commands",
    "commandSetDigest", "conformanceKitRoot", "conformanceKitDigest", "campaignId",
    "campaignDefinitionFileReference", "campaignDefinitionDigest", "campaignReleaseFileReference",
    "campaignReleaseDigest", "launcherDigest", "bundleFileReference", "bundleDigest",
    "allowedEvidenceAxes", "tenantId", "environmentId", "capacityAuthorizationId",
    "capacityAuthorizationFileReference", "capacityAuthorizationDigest", "mutationProfile",
    "admissionPolicyDigest", "resourceQuotaDigest", "endpoints", "issuedAt", "expiresAt",
    "nonce", "releaseTrustStoreDigest", "tenantTrustStoreDigest", "platformSignerKeyId",
    "platformSignature", "tenantSignerKeyId", "tenantSignature",
}
CAPACITY_FIELDS = {
    "schemaVersion", "authorizationId", "operatorId", "tenantId", "environmentId", "namespace",
    "serviceAccountSubject", "permittedEndpointIds", "kubernetesApiRules", "campaignProxyRules",
    "permittedGvksAndVerbs", "preexistingResourceRefs", "resourceQuotaDigest", "limitRangeDigest",
    "preallocatedStorageRefs", "preallocatedAcceleratorRefs", "credentialIdentities", "mutationProfile",
    "admissionPolicyDigest", "validFrom", "expiresAt", "nonce", "signerKeyId", "signature",
}
ENDPOINT_FIELDS = {
    "endpointId", "kind", "ipAddress", "port", "tls", "credentialFileReference",
    "authorizationPolicyDigest", "costDisposition", "accessMode", "discovery",
}
SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}
LIVE_AXES = {"DEPLOYMENT", "RUNTIME", "SECURITY", "ASSURANCE", "TENANT_ACCEPTANCE_CANDIDATE"}


def _require_absolute_reference(value: Any, name: str) -> Path:
    if not isinstance(value, str) or len(value) > 4096:
        raise ConformanceError("INVALID_REFERENCE", f"{name} must be a bounded absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ConformanceError("INVALID_REFERENCE", f"{name} must be an absolute canonical path")
    return path


def command_set_digest(commands: list[list[str]]) -> str:
    return canonical_digest(commands, COMMAND_DOMAIN)


def validate_commands(value: Any) -> list[list[str]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ConformanceError("INVALID_COMMAND_SET", "commands must be a bounded non-empty array")
    commands: list[list[str]] = []
    for command in value:
        if not isinstance(command, list) or not command or len(command) > 32:
            raise ConformanceError("INVALID_COMMAND", "each command must be direct argv")
        if any(not isinstance(argument, str) or not argument or len(argument) > 4096 for argument in command):
            raise ConformanceError("INVALID_COMMAND", "argv entries must be bounded strings")
        executable = Path(command[0]).name.lower()
        if executable in SHELLS or any(character in command[0] for character in "|;&`$<>"):
            raise ConformanceError("SHELL_TRANSPORT_FORBIDDEN", "shell command transport is forbidden")
        commands.append(command)
    return commands


def validate_endpoint(document: Any) -> dict[str, Any]:
    endpoint = require_object(document, "endpoint")
    closed(endpoint, ENDPOINT_FIELDS)
    if endpoint["kind"] not in ("KUBERNETES_API_PROXY", "CAMPAIGN_PROXY", "LOCAL_REGISTRY", "LOCAL_EVIDENCE_SINK"):
        raise ConformanceError("ENDPOINT_KIND_FORBIDDEN", "endpoint kind is not allowed")
    expected_access = "PREAUTHORIZED_PROXY" if endpoint["kind"].endswith("PROXY") else "LOCAL_PREEXISTING"
    if endpoint["accessMode"] != expected_access or endpoint["discovery"] is not False:
        raise ConformanceError("ENDPOINT_AUTHORITY_INVALID", "endpoint access or discovery mode is invalid")
    try:
        address = ipaddress.ip_address(endpoint["ipAddress"])
    except ValueError as exc:
        raise ConformanceError("ENDPOINT_IP_INVALID", "endpoint must use one IP literal") from exc
    if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved or not (address.is_loopback or address.is_private):
        raise ConformanceError("PUBLIC_ENDPOINT_FORBIDDEN", "endpoint must be a private or loopback literal")
    if not isinstance(endpoint["port"], int) or isinstance(endpoint["port"], bool) or not 1 <= endpoint["port"] <= 65535:
        raise ConformanceError("ENDPOINT_PORT_INVALID", "endpoint port is invalid")
    tls = require_object(endpoint["tls"], "endpoint TLS")
    closed(tls, ("serverName", "serverSpkiDigest", "caCertificateFileReference"))
    if not isinstance(tls["serverName"], str) or not tls["serverName"] or "*" in tls["serverName"]:
        raise ConformanceError("TLS_IDENTITY_INVALID", "wildcard or empty TLS identity is forbidden")
    require_digest(tls["serverSpkiDigest"], "serverSpkiDigest")
    _require_absolute_reference(tls["caCertificateFileReference"], "caCertificateFileReference")
    _require_absolute_reference(endpoint["credentialFileReference"], "credentialFileReference")
    require_digest(endpoint["authorizationPolicyDigest"], "authorizationPolicyDigest")
    if endpoint["costDisposition"] not in ("SELF_HOSTED_OPEN_SOURCE_NON_METERED", "TENANT_SUPPLIED_OPEN_SOURCE_NON_METERED"):
        raise ConformanceError("COST_DISPOSITION_FORBIDDEN", "endpoint cost disposition is not non-metered")
    return endpoint


def validate_envelope(document: Any, *, now: datetime | None = None) -> dict[str, Any]:
    envelope = require_object(document, "live execution envelope")
    closed(envelope, ENVELOPE_FIELDS)
    if envelope["schemaVersion"] != ENVELOPE_SCHEMA:
        raise ConformanceError("UNSUPPORTED_ENVELOPE", "unsupported execution-envelope schema")
    if not isinstance(envelope["packetId"], str) or not envelope["packetId"].startswith("CONF-"):
        raise ConformanceError("PACKET_ID_INVALID", "live execution requires a conformance packet")
    for field in ("packetDigest", "commandSetDigest", "conformanceKitDigest", "campaignDefinitionDigest", "campaignReleaseDigest", "launcherDigest", "bundleDigest", "capacityAuthorizationDigest", "admissionPolicyDigest", "resourceQuotaDigest", "releaseTrustStoreDigest", "tenantTrustStoreDigest"):
        require_digest(envelope[field], field)
    commands = validate_commands(envelope["commands"])
    if envelope["commandSetDigest"] != command_set_digest(commands):
        raise ConformanceError("COMMAND_DIGEST_MISMATCH", "command-set digest does not match")
    for field in ("packetFileReference", "conformanceKitRoot", "campaignDefinitionFileReference", "campaignReleaseFileReference", "bundleFileReference", "capacityAuthorizationFileReference"):
        _require_absolute_reference(envelope[field], field)
    axes = envelope["allowedEvidenceAxes"]
    if not isinstance(axes, list) or not axes or len(axes) != len(set(axes)) or any(axis not in LIVE_AXES for axis in axes):
        raise ConformanceError("EVIDENCE_AXES_INVALID", "live evidence axes are invalid")
    if envelope["mutationProfile"] != "ZERO_INCREMENTAL_COST_KUBERNETES_V1":
        raise ConformanceError("MUTATION_PROFILE_FORBIDDEN", "zero incremental cost mutation profile is required")
    endpoints = envelope["endpoints"]
    if not isinstance(endpoints, list) or not endpoints or len(endpoints) > 32:
        raise ConformanceError("ENDPOINT_SET_INVALID", "endpoint set must be bounded and non-empty")
    validated = [validate_endpoint(item) for item in endpoints]
    ids = [item["endpointId"] for item in validated]
    if len(ids) != len(set(ids)):
        raise ConformanceError("DUPLICATE_ENDPOINT", "endpoint IDs must be unique")
    issued = require_time(envelope["issuedAt"], "issuedAt")
    expires = require_time(envelope["expiresAt"], "expiresAt")
    if issued >= expires:
        raise ConformanceError("INVALID_VALIDITY_WINDOW", "envelope validity window is not ordered")
    instant = now or datetime.now(timezone.utc)
    if not issued <= instant <= expires:
        raise ConformanceError("ENVELOPE_NOT_CURRENT", "execution envelope is not current")
    require_key_id(envelope["platformSignerKeyId"], "platformSignerKeyId")
    require_key_id(envelope["tenantSignerKeyId"], "tenantSignerKeyId")
    if envelope["platformSignerKeyId"] == envelope["tenantSignerKeyId"]:
        raise ConformanceError("SIGNER_ROLES_NOT_INDEPENDENT", "platform and tenant signer keys must differ")
    b64url_decode(envelope["platformSignature"], expected_length=64)
    b64url_decode(envelope["tenantSignature"], expected_length=64)
    return envelope


def validate_capacity(document: Any, envelope: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    capacity = require_object(document, "capacity authorization")
    closed(capacity, CAPACITY_FIELDS)
    if capacity["schemaVersion"] != CAPACITY_SCHEMA:
        raise ConformanceError("UNSUPPORTED_CAPACITY", "unsupported capacity schema")
    equal_fields = {
        "authorizationId": "capacityAuthorizationId",
        "tenantId": "tenantId",
        "environmentId": "environmentId",
        "resourceQuotaDigest": "resourceQuotaDigest",
        "mutationProfile": "mutationProfile",
        "admissionPolicyDigest": "admissionPolicyDigest",
    }
    for capacity_field, envelope_field in equal_fields.items():
        if capacity[capacity_field] != envelope[envelope_field]:
            raise ConformanceError("CAPACITY_BINDING_MISMATCH", f"{capacity_field} does not match envelope")
    require_digest(capacity["limitRangeDigest"], "limitRangeDigest")
    for name in ("kubernetesApiRules", "campaignProxyRules", "permittedGvksAndVerbs", "preexistingResourceRefs", "preallocatedStorageRefs", "preallocatedAcceleratorRefs", "credentialIdentities"):
        if not isinstance(capacity[name], list) or len(capacity[name]) > 256:
            raise ConformanceError("CAPACITY_RULES_INVALID", f"{name} must be a bounded array")
    endpoint_ids = {item["endpointId"] for item in envelope["endpoints"]}
    if not isinstance(capacity["permittedEndpointIds"], list) or set(capacity["permittedEndpointIds"]) != endpoint_ids:
        raise ConformanceError("CAPACITY_ENDPOINT_MISMATCH", "capacity endpoint IDs do not match envelope")
    valid_from = require_time(capacity["validFrom"], "validFrom")
    expires = require_time(capacity["expiresAt"], "expiresAt")
    if not (require_time(envelope["issuedAt"], "issuedAt") <= valid_from <= now <= expires <= require_time(envelope["expiresAt"], "expiresAt")):
        raise ConformanceError("CAPACITY_NOT_CURRENT", "capacity window is invalid or wider than envelope")
    require_key_id(capacity["signerKeyId"], "capacity signerKeyId")
    b64url_decode(capacity["signature"], expected_length=64)
    return capacity


def _trust_key(bundle: dict[str, Any], key_id: str, purpose: str, tenant_id: str | None, environment_id: str | None, now: datetime) -> bytes:
    bundle = require_object(bundle, "trust bundle")
    closed(bundle, ("schemaVersion", "keys", "revocationsDigest"))
    if bundle["schemaVersion"] != "harness.planeon.ai/live-trust-bundle/v1alpha1":
        raise ConformanceError("UNSUPPORTED_TRUST_BUNDLE", "unsupported live trust bundle")
    require_digest(bundle["revocationsDigest"], "revocationsDigest")
    matches = [item for item in bundle["keys"] if isinstance(item, dict) and item.get("keyId") == key_id]
    if len(matches) != 1:
        raise ConformanceError("AMBIGUOUS_TRUST_KEY", "trust key must resolve exactly once")
    key = matches[0]
    closed(key, ("keyId", "purpose", "publicKey", "owner", "tenantId", "environmentId", "validFrom", "validUntil", "revoked"))
    if key["purpose"] != purpose or key["tenantId"] != tenant_id or key["environmentId"] != environment_id:
        raise ConformanceError("TRUST_SCOPE_MISMATCH", "trust key purpose or scope mismatch")
    if key["revoked"] is not False:
        raise ConformanceError("TRUST_KEY_REVOKED", "trust key is revoked")
    if not require_time(key["validFrom"], "validFrom") <= now <= require_time(key["validUntil"], "validUntil"):
        raise ConformanceError("TRUST_KEY_NOT_CURRENT", "trust key is not current")
    return b64url_decode(key["publicKey"], expected_length=32)


def verify_live_signatures(envelope: dict[str, Any], capacity: dict[str, Any], release_trust: dict[str, Any], tenant_trust: dict[str, Any], *, now: datetime) -> None:
    platform_key = _trust_key(release_trust, envelope["platformSignerKeyId"], "PLATFORM_RELEASE", None, None, now)
    tenant_key = _trust_key(tenant_trust, envelope["tenantSignerKeyId"], "TENANT_LIVE_EXECUTION", envelope["tenantId"], envelope["environmentId"], now)
    capacity_key = _trust_key(tenant_trust, capacity["signerKeyId"], "CAPACITY_OPERATOR", envelope["tenantId"], envelope["environmentId"], now)
    if len({platform_key, tenant_key, capacity_key}) != 3:
        raise ConformanceError("SIGNER_ROLES_NOT_INDEPENDENT", "all live signer keys must be distinct")
    envelope_payload = signature_payload(ENVELOPE_DOMAIN, envelope, ("platformSignature", "tenantSignature"))
    if not verify(platform_key, envelope_payload, b64url_decode(envelope["platformSignature"], expected_length=64)):
        raise ConformanceError("PLATFORM_SIGNATURE_INVALID", "platform signature is invalid")
    if not verify(tenant_key, envelope_payload, b64url_decode(envelope["tenantSignature"], expected_length=64)):
        raise ConformanceError("TENANT_SIGNATURE_INVALID", "tenant signature is invalid")
    capacity_payload = signature_payload(CAPACITY_DOMAIN, capacity, ("signature",))
    if not verify(capacity_key, capacity_payload, b64url_decode(capacity["signature"], expected_length=64)):
        raise ConformanceError("CAPACITY_SIGNATURE_INVALID", "capacity signature is invalid")


def tree_digest(root: Path) -> str:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ConformanceError("KIT_ROOT_INVALID", "kit root must be an absolute regular directory")
    entries: list[dict[str, Any]] = []
    seen_inodes: set[tuple[int, int]] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort(key=lambda item: item.encode("utf-8"))
        files.sort(key=lambda item: item.encode("utf-8"))
        for name in list(directories):
            path = Path(current) / name
            if path.is_symlink():
                raise ConformanceError("KIT_LINK_FORBIDDEN", "kit tree contains a symlink")
        for name in files:
            path = Path(current) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
                raise ConformanceError("KIT_FILE_INVALID", "kit files must be regular and not writable by group or other")
            inode = (info.st_dev, info.st_ino)
            if inode in seen_inodes:
                raise ConformanceError("KIT_HARDLINK_FORBIDDEN", "kit tree contains a hard-link alias")
            seen_inodes.add(inode)
            relative = path.relative_to(root).as_posix()
            data = secure_read(path)
            entries.append({"mode": f"{stat.S_IMODE(info.st_mode):04o}", "path": relative, "sha256": byte_digest(data), "size": len(data)})
    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    return canonical_digest(entries, TREE_DOMAIN)


def _verify_reference(path_value: str, expected_digest: str) -> bytes:
    data = secure_read(Path(path_value), require_absolute=True)
    if byte_digest(data) != expected_digest:
        raise ConformanceError("REFERENCE_DIGEST_MISMATCH", "local reference digest does not match")
    return data


def preflight(
    envelope_path: Path,
    *,
    launcher_path: Path,
    release_trust_path: Path = FIXED_RELEASE_TRUST,
    tenant_trust_path: Path = FIXED_TENANT_TRUST,
    now: datetime | None = None,
) -> dict[str, Any]:
    instant = now or datetime.now(timezone.utc)
    envelope = validate_envelope(load_json(envelope_path, require_absolute=True), now=instant)
    if byte_digest(secure_read(launcher_path, require_absolute=True)) != envelope["launcherDigest"]:
        raise ConformanceError("LAUNCHER_DIGEST_MISMATCH", "installed launcher digest does not match")
    _verify_reference(envelope["packetFileReference"], envelope["packetDigest"])
    _verify_reference(envelope["campaignDefinitionFileReference"], envelope["campaignDefinitionDigest"])
    _verify_reference(envelope["campaignReleaseFileReference"], envelope["campaignReleaseDigest"])
    _verify_reference(envelope["bundleFileReference"], envelope["bundleDigest"])
    capacity_bytes = _verify_reference(envelope["capacityAuthorizationFileReference"], envelope["capacityAuthorizationDigest"])
    if tree_digest(Path(envelope["conformanceKitRoot"])) != envelope["conformanceKitDigest"]:
        raise ConformanceError("KIT_DIGEST_MISMATCH", "conformance kit tree digest does not match")
    release_bytes = secure_read(release_trust_path, require_absolute=True)
    tenant_bytes = secure_read(tenant_trust_path, require_absolute=True)
    if byte_digest(release_bytes) != envelope["releaseTrustStoreDigest"] or byte_digest(tenant_bytes) != envelope["tenantTrustStoreDigest"]:
        raise ConformanceError("TRUST_STORE_DIGEST_MISMATCH", "fixed trust-store digest does not match")
    capacity = validate_capacity(load_json_bytes(capacity_bytes), envelope, now=instant)
    verify_live_signatures(envelope, capacity, load_json_bytes(release_bytes), load_json_bytes(tenant_bytes), now=instant)
    return {
        "authorityStatus": "PASS",
        "campaignId": envelope["campaignId"],
        "capacityAuthorizationId": envelope["capacityAuthorizationId"],
        "environmentId": envelope["environmentId"],
        "tenantId": envelope["tenantId"],
    }
