#!/usr/bin/env python3
"""I06 backend profile (W02g): distribution selection criteria and identity closure.

DATA_CHECK_ONLY reference model for the sealed single-node qualification control plane
(profile SEALED_SINGLE_NODE_CONTROL_PLANE_V1) on the Kubernetes v1.37.1 baseline.

- `check_inventory` checks the writer inventory against the cited upstream facts.
- `check_closure` checks the identity closure against the upstream bootstrap RBAC and the
  profile: upstream identities hold exactly their bootstrap-derived grants, the planeon
  identities are a closed set with fixed grants, and full authority belongs only to
  system:masters, whose only member is the apiserver's loopback client (W01 review finding F1).
- `check_evidence` checks a distribution evidence record (what W03's selected distribution
  declares about its configuration), bound to its W02a backend profile, against selection
  criteria SC00-SC15.
- `check_rbac_snapshot` checks an effective-RBAC snapshot (what the policy observer computes
  from RBAC objects) against a checked closure (IC00-IC05).

None of them inspects a cluster, grants authority or selects a distribution. Every refusal
names the criterion or closure rule it breaks.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

EVIDENCE_VERSION = "planeon.internal.i06-distribution-evidence/v1"
SNAPSHOT_VERSION = "planeon.internal.i06-rbac-snapshot/v1"
INVENTORY_VERSION = "planeon.internal.i06-writer-inventory/v1"
CLOSURE_VERSION = "planeon.internal.i06-identity-closure/v1"
BOOTSTRAP_VERSION = "planeon.internal.i06-upstream-bootstrap-rbac/v1"
KUBERNETES_VERSION = "v1.37.1"
PROFILE = "SEALED_SINGLE_NODE_CONTROL_PLANE_V1"
# W02a backendProfile.implementationId (architecture/native-profile-v2/qualification.schema.json).
IMPLEMENTATION_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{0,127}")
TEST_FIXTURES = ("unit-distribution",)
COMPONENTS = ("APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET",
              "NETWORK_POLICY_AGENT", "SCHEDULER", "SERVICE_PROXY")
# W02a admits six to eight components: the service proxy and network-policy agent are optional.
REQUIRED_COMPONENTS = ("APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET", "SCHEDULER")
# Mirrors W02a's per-component confined types (backendComponents processLabel).
COMPONENT_TYPES = {"APISERVER": "qualk8s_apiserver_t", "CONTAINER_RUNTIME": "qualk8s_runtime_t",
                   "CONTROLLER_MANAGER": "qualk8s_controller_manager_t", "DATASTORE": "qualk8s_datastore_t",
                   "KUBELET": "qualk8s_kubelet_t", "NETWORK_POLICY_AGENT": "qualk8s_netpol_t",
                   "SCHEDULER": "qualk8s_scheduler_t", "SERVICE_PROXY": "qualk8s_proxy_t"}
# Kubernetes components that take --feature-gates.
GATED_COMPONENTS = ("APISERVER", "CONTROLLER_MANAGER", "KUBELET", "SCHEDULER", "SERVICE_PROXY")
HOLDERS = COMPONENTS + ("EFFECT_GATE", "OBSERVER")
REQUIRED_ADMISSION = ("NamespaceLifecycle", "LimitRanger", "ServiceAccount", "ResourceQuota", "NodeRestriction",
                      "ValidatingAdmissionPolicy", "PodSecurity", "CertificateApproval", "CertificateSigning")
FORBIDDEN_ADMISSION = ("MutatingAdmissionWebhook", "ValidatingAdmissionWebhook", "MutatingAdmissionPolicy",
                       "ImagePolicyWebhook", "NamespaceAutoProvision", "AlwaysAdmit")
# The v1.37 default-on set (pkg/kubeapiserver/options/plugins.go) minus the forbidden plugins, plus
# NodeRestriction and four off-by-default plugins that only restrict requests.
ALLOWED_ADMISSION = (
    "CertificateApproval", "CertificateSigning", "CertificateSubjectRestriction", "ClusterTrustBundleAttest",
    "DefaultIngressClass", "DefaultStorageClass", "DefaultTolerationSeconds", "LimitRanger", "NamespaceLifecycle",
    "NodeDeclaredFeatureValidator", "PersistentVolumeClaimResize", "PodGroupProtection", "PodResizeValidator",
    "PodSecurity", "PodTopologyLabels", "Priority", "ResourceQuota", "RuntimeClass", "ServiceAccount",
    "StorageObjectInUseProtection", "TaintNodesByCondition", "ValidatingAdmissionPolicy",
    "NodeRestriction", "AlwaysPullImages", "DenyServiceExternalIPs", "EventRateLimit",
    "OwnerReferencesPermissionEnforcement")
LICENSES = ("Apache-2.0",)
SEALED_FILES = ("ADMISSION_CONFIG", "APISERVER_FLAGS", "AUTHORIZATION_CONFIG", "CNI_CONFIG", "COMPONENT_DEFINITIONS",
                "CONTAINER_RUNTIME_CONFIG", "CONTROLLER_MANAGER_FLAGS", "DATASTORE_CONFIG", "ENCRYPTION_CONFIG",
                "KUBECONFIGS", "KUBELET_CONFIG", "PKI_TRUST_BUNDLES", "SCHEDULER_FLAGS")
# Sealed exactly when the record uses them: an admission manifest directory, an authentication
# configuration file and an audit policy are reloaded or read at start; optional components bring
# their own configuration.
CONDITIONAL_SEALED_FILES = ("ADMISSION_MANIFESTS", "AUDIT_CONFIG", "AUTHENTICATION_CONFIG",
                            "NETWORK_POLICY_AGENT_CONFIG", "SERVICE_PROXY_CONFIG")

REQUIRED_DISABLED_CONTROLLERS = (
    "bootstrap-signer-controller", "certificatesigningrequest-approving-controller",
    "certificatesigningrequest-cleaner-controller", "certificatesigningrequest-signing-controller",
    "clusterrole-aggregation-controller", "kube-apiserver-serving-clustertrustbundle-publisher-controller",
    "legacy-serviceaccount-token-cleaner-controller", "serviceaccount-token-controller",
    "storage-version-migrator-controller", "token-cleaner-controller")
CONTROLLER_DISPOSITIONS = {"garbage-collector-controller": "OWNERREF_RULE", "namespace-controller": "I07_TRIGGERED_ONLY",
                           "resourcequota-controller": "STATUS_ONLY", "serviceaccount-controller": "I07_TRIGGERED_ONLY",
                           "validatingadmissionpolicy-status-controller": "STATUS_ONLY"}
WRITER_DISPOSITIONS = {
    "rbac/bootstrap-roles": "STARTUP_BEFORE_INSPECTING",
    "start-system-namespaces-controller": "SYSTEM_NAMESPACES_ONLY",
    "start-cluster-authentication-info-controller": "SYSTEM_NAMESPACES_ONLY",
    "priority-and-fairness-config-producer": "AVAILABILITY_ONLY",
    "priority-and-fairness-config-consumer": "STATUS_ONLY",
    "kube-apiserver-autoregistration": "LOCAL_APISERVICES_ONLY",
    "apiservice-status-local-available-controller": "STATUS_ONLY",
    "apiservice-status-remote-available-controller": "STATUS_ONLY",
    "start-apiextensions-controllers": "ABSENT_BY_PROFILE",
    "ResourceQuota admission plugin (in-process, request-driven)": "STATUS_ONLY",
    "NamespaceAutoProvision admission plugin (in-process, request-driven)": "REQUIRED_DISABLED",
}

WRITE_VERBS = ("create", "update", "patch", "delete", "deletecollection")
# (apiGroup, resource) pairs whose writes change a policy fact (spec section 2.3).
POLICY_RESOURCES = {
    ("", "namespaces"), ("", "namespaces/finalize"), ("", "resourcequotas"), ("", "limitranges"),
    ("", "serviceaccounts"),
    ("rbac.authorization.k8s.io", "roles"), ("rbac.authorization.k8s.io", "rolebindings"),
    ("rbac.authorization.k8s.io", "clusterroles"), ("rbac.authorization.k8s.io", "clusterrolebindings"),
    ("networking.k8s.io", "networkpolicies"),
    ("admissionregistration.k8s.io", "validatingadmissionpolicies"),
    ("admissionregistration.k8s.io", "validatingadmissionpolicybindings"),
    ("admissionregistration.k8s.io", "mutatingadmissionpolicies"),
    ("admissionregistration.k8s.io", "mutatingadmissionpolicybindings"),
    ("admissionregistration.k8s.io", "validatingwebhookconfigurations"),
    ("admissionregistration.k8s.io", "mutatingwebhookconfigurations"),
    ("apiregistration.k8s.io", "apiservices"), ("apiextensions.k8s.io", "customresourcedefinitions"),
    ("certificates.k8s.io", "certificatesigningrequests/approval"),
    ("certificates.k8s.io", "certificatesigningrequests/status"),
    ("flowcontrol.apiserver.k8s.io", "flowschemas"), ("flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations"),
}
STATUS_RESOURCES = {("", "resourcequotas/status"), ("", "namespaces/status"),
                    ("admissionregistration.k8s.io", "validatingadmissionpolicies/status"),
                    ("apiregistration.k8s.io", "apiservices/status"),
                    ("apiextensions.k8s.io", "customresourcedefinitions/status"),
                    ("flowcontrol.apiserver.k8s.io", "flowschemas/status"),
                    ("flowcontrol.apiserver.k8s.io", "prioritylevelconfigurations/status")}
# The kubelet maps HTTP methods to these verbs on its subresources, so each reaches the kubelet API.
KUBELET_VERBS = ("get", "create", "update", "patch", "delete")
# Verbs that escalate or obtain another identity's authority (spec section 2.3 closure rules).
SPECIAL_TARGETS = {
    ("rbac.authorization.k8s.io", "roles"): ("escalate", "bind"),
    ("rbac.authorization.k8s.io", "clusterroles"): ("escalate", "bind"),
    # Legacy impersonation checks users/groups/serviceaccounts in the core group; constrained
    # impersonation (beta, default on since 1.36) checks impersonate:<mode> in authentication.k8s.io.
    ("", "users"): ("impersonate",), ("", "groups"): ("impersonate",), ("", "serviceaccounts"): ("impersonate",),
    ("authentication.k8s.io", "users"): ("impersonate",), ("authentication.k8s.io", "groups"): ("impersonate",),
    ("authentication.k8s.io", "serviceaccounts"): ("impersonate",), ("authentication.k8s.io", "nodes"): ("impersonate",),
    ("authentication.k8s.io", "uids"): ("impersonate",), ("authentication.k8s.io", "userextras/*"): ("impersonate",),
    ("authentication.k8s.io", "admissionReviewAPIGroups"): ("attest",),
    ("", "serviceaccounts/token"): ("create",),
    ("certificates.k8s.io", "signers"): ("approve", "sign", "attest"),
    # nodes/proxy reaches exec over a websocket GET; nodes/log serves node log files; nodes/checkpoint
    # dumps container memory.
    ("", "nodes/proxy"): KUBELET_VERBS, ("", "nodes/log"): KUBELET_VERBS, ("", "nodes/checkpoint"): KUBELET_VERBS,
    ("", "nodes"): ("proxy",),
    # get counts as well as create: websocket exec needs create only while the default gate holds.
    ("", "pods/exec"): ("create", "get"), ("", "pods/attach"): ("create", "get"),
}
# Creating or changing pods (directly or through a pod-creating kind) in a namespace runs code as any
# service account of that namespace, so these grants matter at cluster scope and in protected namespaces.
WORKLOAD_RESOURCES = {("", "pods"), ("", "pods/ephemeralcontainers"), ("", "replicationcontrollers"),
                      ("apps", "daemonsets"), ("apps", "deployments"), ("apps", "replicasets"), ("apps", "statefulsets"),
                      ("batch", "cronjobs"), ("batch", "jobs")}
WORKLOAD_VERBS = ("create", "update", "patch")
PROTECTED_NAMESPACES = ("kube-system",)
SYSTEM_NAMESPACES = ("default", "kube-node-lease", "kube-public", "kube-system")
# Scopes are CLUSTER (ClusterRoleBinding) or a namespace name; neither placeholder is a valid namespace name.
CLUSTER = "CLUSTER"
QUALIFICATION_SCOPE = "QUALIFICATION_NAMESPACE"
# The I07 policy writer: namespaced policy kinds and its own namespace object in the qualification namespace;
# admission policies and bindings at cluster scope (W02f may move A2 policies to sealed manifests).
WRITER_SCOPES = {"/limitranges": QUALIFICATION_SCOPE, "/namespaces": QUALIFICATION_SCOPE, "/resourcequotas": QUALIFICATION_SCOPE,
                 "/serviceaccounts": QUALIFICATION_SCOPE, "networking.k8s.io/networkpolicies": QUALIFICATION_SCOPE,
                 "rbac.authorization.k8s.io/rolebindings": QUALIFICATION_SCOPE, "rbac.authorization.k8s.io/roles": QUALIFICATION_SCOPE,
                 "admissionregistration.k8s.io/validatingadmissionpolicies": CLUSTER,
                 "admissionregistration.k8s.io/validatingadmissionpolicybindings": CLUSTER}
WRITER = ("User", "planeon:policy-writer")
WRITER_ROLE_NAMES = ["planeon-gate-effect", "planeon-policy-observer"]
KUBELET_CLIENT = ("User", "planeon:apiserver-kubelet-client")
KUBELET_CLIENT_ROLE = "system:kubelet-api-admin"
# Closed planeon identity set: (holder, mustBePresent). The profile fixes every name; W03 issues the
# credentials (client certificates from the off-host CA) with exactly these subjects.
PROFILE_IDENTITIES = {WRITER: ("EFFECT_GATE", True), ("User", "planeon:effect-gate"): ("EFFECT_GATE", False),
                      ("User", "planeon:policy-observer"): ("OBSERVER", False), KUBELET_CLIENT: ("APISERVER", False),
                      ("User", "planeon:netpol-agent"): ("NETWORK_POLICY_AGENT", False)}
COMPONENT_USERS = {("User", "system:kube-controller-manager"): ("CONTROLLER_MANAGER", True),
                   ("User", "system:kube-scheduler"): ("SCHEDULER", False),
                   ("User", "system:kube-proxy"): ("SERVICE_PROXY", False)}
ALL = [{"category": "ALL", "resource": "*", "verb": "*", "scope": "*"}]
# Full authority is the group's; the loopback user's authority comes only from that membership.
F1_IDENTITIES = {("Group", "system:masters"): ("APISERVER", True, ALL), ("User", "system:apiserver"): ("APISERVER", False, [])}
NODES = ("Group", "system:nodes")
API_CLIENTS = {"SERVICE_PROXY": "system:kube-proxy", "NETWORK_POLICY_AGENT": "planeon:netpol-agent"}
CATEGORIES = ("POLICY_WRITE", "STATUS_WRITE", "SPECIAL", "WORKLOAD")
SA_PREFIX = "system:serviceaccount:"
DNS_LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
PATH = re.compile(r"(/[A-Za-z0-9_.+@-]+)+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _keys(value: Any, keys: set[str], message: str) -> None:
    require(type(value) is dict and set(value) == keys, message)


def _text(value: Any) -> bool:
    return type(value) is str and value != "" and value == value.strip()


def _path(value: Any) -> bool:
    """A canonical absolute path: no empty, '.' or '..' segment and no trailing '/'."""
    return (type(value) is str and PATH.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value[1:].split("/")))


def _zero(value: Any) -> bool:
    return type(value) is int and value == 0


# ---------------------------------------------------------------- grants

def _covers(rule_resource: str, target: str) -> bool:
    """Kubernetes RBAC resource matching: '*' matches everything, '*/sub' matches any '<r>/sub'.
    A target ending in '/*' (userextras/<key>) stands for every subresource key."""
    if rule_resource in ("*", target):
        return True
    base, _, sub = target.partition("/")
    if sub == "*":
        return rule_resource.startswith(base + "/") or (rule_resource.startswith("*/") and len(rule_resource) > 2)
    return sub != "" and rule_resource == "*/" + sub


def _is_special(verb: str, allowed: tuple[str, ...]) -> bool:
    if verb == "*" or verb in allowed:
        return True
    return "impersonate" in allowed and verb.startswith(("impersonate:", "impersonate-on:"))


def _grants(rule: dict) -> set[tuple[str, str, str, str]]:
    """(category, 'group/resource', verb, scope) for every policy-relevant grant in one effective rule."""
    out = set()
    scope = rule["scope"]
    for group, resource in sorted(POLICY_RESOURCES | STATUS_RESOURCES | set(SPECIAL_TARGETS) | WORKLOAD_RESOURCES):
        if not any(g in ("*", group) for g in rule["apiGroups"]) or not any(_covers(r, resource) for r in rule["resources"]):
            continue
        key = "%s/%s" % (group, resource)
        for verb in rule["verbs"]:
            if (group, resource) in SPECIAL_TARGETS and _is_special(verb, SPECIAL_TARGETS[(group, resource)]):
                out.add(("SPECIAL", key, verb, scope))
            if verb in WRITE_VERBS or verb == "*":
                if (group, resource) in POLICY_RESOURCES:
                    out.add(("POLICY_WRITE", key, verb, scope))
                elif (group, resource) in STATUS_RESOURCES:
                    out.add(("STATUS_WRITE", key, verb, scope))
            if ((group, resource) in WORKLOAD_RESOURCES and (verb in WORKLOAD_VERBS or verb == "*")
                    and (scope == CLUSTER or scope in PROTECTED_NAMESPACES)):
                out.add(("WORKLOAD", key, verb, scope))
    return out


def derive_grants(rules: list) -> list[dict]:
    out = set()
    for rule in rules:
        out |= _grants(rule)
    return [{"category": c, "resource": r, "verb": v, "scope": s} for c, r, v, s in sorted(out)]


def writer_grants() -> list[dict]:
    """The policy writer's exact grants: its kinds and scopes, and escalate/bind on the named roles."""
    out = set()
    for resource, scope in WRITER_SCOPES.items():
        for verb in (("update", "patch") if resource == "/namespaces" else ("create", "update", "patch", "delete")):
            out.add(("POLICY_WRITE", resource, verb, scope))
    out |= {("SPECIAL", "rbac.authorization.k8s.io/roles", verb, QUALIFICATION_SCOPE) for verb in ("bind", "escalate")}
    return [{"category": c, "resource": r, "verb": v, "scope": s} for c, r, v, s in sorted(out)]


def _allowed(grant: tuple[str, str, str, str], allowed: list[dict], namespace: str) -> bool:
    category, resource, verb, scope = grant
    for row in allowed:
        if row["category"] == "ALL":
            return True
        row_scope = namespace if row["scope"] == QUALIFICATION_SCOPE else row["scope"]
        if (row["category"] == category and row["resource"] == resource and row["verb"] == verb
                and (row_scope == scope or row_scope == CLUSTER)):
            return True
    return False


def _rule(value: Any, message: str) -> None:
    _keys(value, {"apiGroups", "resources", "verbs", "resourceNames", "scope"}, message)
    for key in ("apiGroups", "resources", "verbs", "resourceNames"):
        require(type(value[key]) is list and all(type(item) is str for item in value[key]), message)
    require(value["scope"] == CLUSTER or (type(value["scope"]) is str and DNS_LABEL.fullmatch(value["scope"]) is not None),
            message)


# ---------------------------------------------------------------- inventory and closure

def check_inventory(inventory: Any, facts: dict) -> None:
    """The writer inventory must project the cited upstream facts and carry the profile's dispositions."""
    _keys(inventory, {"schemaVersion", "kubernetesVersion", "kubernetesCommit", "facts", "controllers", "apiserverWriters"},
          "INV closed inventory")
    require(inventory["schemaVersion"] == INVENTORY_VERSION and inventory["kubernetesVersion"] == facts["version"]
            == KUBERNETES_VERSION and inventory["kubernetesCommit"] == facts["meta"]["commit"], "INV version")
    rows = inventory["controllers"]
    require(type(rows) is list and [row.get("name") for row in rows] == [row["name"] for row in facts["controllers"]],
            "INV controller set differs from the upstream facts")
    for row, fact in zip(rows, facts["controllers"]):
        _keys(row, {"name", "serviceAccount", "defaultState", "policyKindRules", "source", "profile", "disposition", "reason"},
              "INV closed controller row")
        expected_rules = [{k: rule[k] for k in ("apiGroups", "resources", "verbs")} for rule in fact["policyKindRules"]]
        require(row["serviceAccount"] == fact["serviceAccount"] and row["policyKindRules"] == expected_rules
                and row["source"] == fact["source"], "INV controller row differs from the upstream facts: " + row["name"])
        if row["name"] in REQUIRED_DISABLED_CONTROLLERS:
            require(row["profile"] == "REQUIRED_DISABLED" and row["disposition"] == "DISABLED", "INV required-disabled: " + row["name"])
        else:
            expected = CONTROLLER_DISPOSITIONS.get(row["name"], "NOT_POLICY")
            require(row["profile"] == "ALLOWED" and row["disposition"] == expected, "INV disposition: " + row["name"])
            require(expected != "NOT_POLICY" or not row["policyKindRules"], "INV policy-kind writer without a disposition: " + row["name"])
        require(_text(row["reason"]), "INV reason")
    writers = inventory["apiserverWriters"]
    require(type(writers) is list and [w.get("name") for w in writers] == [w["name"] for w in facts["apiserverWriters"]],
            "INV apiserver writer set differs from the upstream facts")
    for row, fact in zip(writers, facts["apiserverWriters"]):
        _keys(row, {"name", "kind", "cadence", "identity", "writesPolicyKinds", "disposition", "reason", "source"},
              "INV closed writer row")
        require(all(row[k] == fact[k] for k in ("kind", "cadence", "identity", "writesPolicyKinds", "source")),
                "INV writer row differs from the upstream facts: " + row["name"])
        expected = WRITER_DISPOSITIONS.get(row["name"], "NOT_POLICY")
        require(row["disposition"] == expected and (expected != "NOT_POLICY" or not row["writesPolicyKinds"]),
                "INV writer disposition: " + row["name"])
        require(_text(row["reason"]), "INV reason")


def _controller_accounts(inventory: dict) -> tuple[set[str], set[str]]:
    """(every controller account, accounts used only by required-disabled controllers)."""
    users: dict[str, set[str]] = {}
    for row in inventory["controllers"]:
        if row["serviceAccount"]:
            users.setdefault(SA_PREFIX + "kube-system:" + row["serviceAccount"], set()).add(row["profile"])
    return set(users), {name for name, profiles in users.items() if profiles == {"REQUIRED_DISABLED"}}


def upstream_rules(bootstrap: Any) -> tuple[dict, dict]:
    """(subject key -> effective bootstrap rules, referenced unbound role -> rules at cluster scope)."""
    _keys(bootstrap, {"schemaVersion", "kubernetesVersion", "kubernetesCommit", "fixtures", "derivation", "subjects",
                      "referencedRoles"}, "CL closed bootstrap RBAC")
    require(bootstrap["schemaVersion"] == BOOTSTRAP_VERSION and bootstrap["kubernetesVersion"] == KUBERNETES_VERSION,
            "CL bootstrap version")
    subjects = {}
    for subject in bootstrap["subjects"]:
        _keys(subject, {"kind", "name", "rules"}, "CL closed bootstrap subject")
        for rule in subject["rules"]:
            _keys(rule, {"apiGroups", "resources", "verbs", "resourceNames", "scope", "binding"}, "CL closed bootstrap rule")
        require((subject["kind"], subject["name"]) not in subjects, "CL duplicate bootstrap subject")
        subjects[(subject["kind"], subject["name"])] = [{k: v for k, v in rule.items() if k != "binding"}
                                                        for rule in subject["rules"]]
    roles = {}
    for name, role in bootstrap["referencedRoles"].items():
        _keys(role, {"fixture", "rules"}, "CL closed referenced role")
        require(role["fixture"] in bootstrap["fixtures"], "CL referenced role outside the pinned fixtures")
        for rule in role["rules"]:
            _keys(rule, {"apiGroups", "resources", "verbs", "resourceNames"}, "CL closed referenced role rule")
        roles[name] = [dict(rule, scope=CLUSTER) for rule in role["rules"]]
    return subjects, roles


def check_closure(closure: Any, inventory: dict, bootstrap: Any) -> None:
    """Every closure entry is pinned by its derivation; every upstream subject with a policy-relevant
    grant is in the closure or is the dormant account of required-disabled controllers."""
    _keys(closure, {"schemaVersion", "kubernetesVersion", "scopes", "identities"}, "CL closed closure")
    require(closure["schemaVersion"] == CLOSURE_VERSION and closure["kubernetesVersion"] == KUBERNETES_VERSION, "CL version")
    upstream, roles = upstream_rules(bootstrap)
    accounts, dormant = _controller_accounts(inventory)
    entries = {}
    for entry in closure["identities"]:
        _keys(entry, {"kind", "name", "holder", "derivation", "mustBePresent", "allowedGrants", "resourceNames", "note"},
              "CL closed identity entry")
        key = (entry["kind"], entry["name"])
        require(key not in entries, "CL duplicate identity")
        entries[key] = entry
        require(entry["kind"] in ("User", "Group", "ServiceAccount") and _text(entry["name"]) and entry["holder"] in HOLDERS
                and type(entry["mustBePresent"]) is bool and _text(entry["note"]), "CL identity entry")
        require((entry["kind"] == "ServiceAccount") == entry["name"].startswith(SA_PREFIX), "CL service-account naming")
        grants = entry["allowedGrants"]
        require(type(grants) is list, "CL grants")
        for row in grants:
            _keys(row, {"category", "resource", "verb", "scope"}, "CL closed grant")
        pinned = (entry["holder"], entry["mustBePresent"])
        derivation = entry["derivation"]
        if derivation == "F1_LOOPBACK":
            require(key in F1_IDENTITIES and pinned == F1_IDENTITIES[key][:2] and grants == F1_IDENTITIES[key][2],
                    "CL full authority only for system:masters; the loopback user holds no RBAC grant (F1)")
        else:
            require(all(row["category"] in CATEGORIES for row in grants),
                    "CL full authority only for system:masters; the loopback user holds no RBAC grant (F1)")
            if derivation == "BOOTSTRAP_SUBJECT":
                require(key in upstream and grants == derive_grants(upstream[key]),
                        "CL closure grants differ from the upstream bootstrap derivation: " + entry["name"])
                if entry["kind"] == "ServiceAccount":
                    require(entry["name"] in accounts - dormant and pinned == ("CONTROLLER_MANAGER", False),
                            "CL closure service account outside the allowed controllers: " + entry["name"])
                else:
                    require(key in COMPONENT_USERS and pinned == COMPONENT_USERS[key], "CL component identity: " + entry["name"])
            elif derivation == "NODE_AUTHORIZER":
                require(key == NODES and grants == [] and pinned == ("KUBELET", False), "CL node authorizer entry")
            else:
                require(derivation == "PROFILE" and key in PROFILE_IDENTITIES,
                        "CL identity outside the closed profile set: " + entry["name"])
                require(pinned == PROFILE_IDENTITIES[key], "CL profile identity holder or presence differs: " + entry["name"])
                expected =(writer_grants() if key == WRITER else
                            derive_grants(roles[KUBELET_CLIENT_ROLE]) if key == KUBELET_CLIENT else [])
                require(grants == expected, "CL profile identity grants differ from the profile: " + entry["name"])
        require(entry["resourceNames"] == (WRITER_ROLE_NAMES if key == WRITER else None),
                "CL resourceNames: only the policy writer names exactly the planeon roles")
    for key, rules in upstream.items():
        if derive_grants(rules) and key not in entries:
            require(key[0] == "ServiceAccount" and key[1] in dormant,
                    "CL upstream subject with policy-relevant grants outside the closure: " + key[1])
    for key in list(F1_IDENTITIES) + list(COMPONENT_USERS) + list(PROFILE_IDENTITIES) + [NODES]:
        require(key in entries, "CL required identity missing: " + key[1])


# ---------------------------------------------------------------- evidence record

def check_evidence(record: Any, inventory: dict, backend: Any, production: bool = True) -> None:
    """Check one distribution evidence record, bound to its W02a backend profile, against SC00-SC15."""
    _keys(record, {"schemaVersion", "implementationId", "testOnly", "kubernetesVersion", "distribution", "artifacts",
                   "components", "datastore", "apiserver", "controllerManager", "kubelet", "versioning",
                   "credentialsOnHost", "apiClients", "runtimeSocket", "sealedConfiguration"},
          "SC00 closed evidence record")
    require(record["schemaVersion"] == EVIDENCE_VERSION, "SC00 evidence version")
    implementation = record["implementationId"]
    require(type(implementation) is str and IMPLEMENTATION_PATTERN.fullmatch(implementation) is not None,
            "SC00 implementation identifier outside the W02a pattern")
    _keys(backend, {"backendProfile", "backendComponents"}, "SC00 W02a backend")
    profile = backend["backendProfile"]
    _keys(profile, {"profile", "implementationId", "componentKeys"}, "SC00 W02a backend profile")
    require(profile["profile"] == PROFILE and profile["implementationId"] == implementation,
            "SC00 evidence bound to a different W02a backend profile")
    require(type(record["testOnly"]) is bool and (implementation not in TEST_FIXTURES or record["testOnly"] is True),
            "SC00 unit-distribution is a test-only implementation profile")
    dist = record["distribution"]
    _keys(dist, {"name", "version", "license"}, "SC13 distribution identity")
    require(_text(dist["name"]) and _text(dist["version"]), "SC13 distribution identity")
    if production:
        require(record["testOnly"] is False, "SC00 test-only implementation profile cannot qualify a production backend")
        require(implementation not in TEST_FIXTURES and dist["name"] not in TEST_FIXTURES,
                "SC00 the unit-distribution fixture identity cannot qualify a production backend")
    require(record["kubernetesVersion"] == KUBERNETES_VERSION, "SC14 Kubernetes release differs from the v1.37.1 baseline")
    require(dist["license"] in LICENSES, "SC13 license outside the allowed set")
    art = record["artifacts"]
    _keys(art, {"pinned", "offline", "runtimeDownloads", "autoUpdate"}, "SC13 artifact closure")
    require(art["pinned"] is True and art["offline"] is True and art["runtimeDownloads"] is False
            and art["autoUpdate"] is False, "SC13 artifacts must be pinned and offline, with no downloads or auto-update")

    keys = profile["componentKeys"]
    require(type(keys) is list and all(type(name) is str for name in keys) and len(set(keys)) == len(keys)
            and set(REQUIRED_COMPONENTS) <= set(keys) <= set(COMPONENTS),
            "SC08 component set outside the W02a implementation profile")
    components, rows = record["components"], backend["backendComponents"]
    require(type(components) is dict and set(components) == set(keys) and type(rows) is dict and set(rows) == set(keys),
            "SC08 component set differs from the W02a implementation profile")
    for name in sorted(keys):
        _keys(components[name], {"separateProcess"}, "SC08 component entry")
        require(components[name]["separateProcess"] is True, "SC08 component not a separate process: " + name)
        row = rows[name]
        require(type(row) is dict and row.get("processLabel") == "system_u:system_r:%s:s0" % COMPONENT_TYPES[name],
                "SC08 component outside its confined type: " + name)
        require(_path(row.get("executable")), "SC08 component executable must be a canonical absolute path: " + name)
        require(type(row.get("artifactDigest")) is str and DIGEST.fullmatch(row["artifactDigest"]) is not None,
                "SC08 component artifact digest: " + name)
    require(len({rows[name]["executable"] for name in keys}) == len(keys)
            and len({rows[name]["artifactDigest"] for name in keys}) == len(keys),
            "SC08 components must use distinct executables with distinct content (one entry type per confined domain)")

    store = record["datastore"]
    _keys(store, {"clientListen", "peerListen", "members"}, "SC01 datastore entry")
    require(type(store["clientListen"]) is list and store["clientListen"]
            and all(type(url) is str and url.startswith("unix:///") and _path(url[7:]) for url in store["clientListen"])
            and store["peerListen"] == [] and type(store["members"]) is int and store["members"] == 1,
            "SC01 datastore must listen on AF_UNIX only, with one member and no peers")

    api = record["apiserver"]
    _keys(api, {"bindAddress", "securePort", "authentication", "authorization", "admissionPlugins", "admissionManifestsDir",
                "auditPolicyFile", "apiServices", "customResourceDefinitions", "serviceAccountTokens"}, "SC02 apiserver entry")
    try:
        loopback = type(api["bindAddress"]) is str and ipaddress.ip_address(api["bindAddress"]).is_loopback
    except ValueError:
        loopback = False
    require(loopback and type(api["securePort"]) is int and 1 <= api["securePort"] <= 65535,
            "SC02 apiserver must bind a loopback address")
    authn = api["authentication"]
    _keys(authn, {"anonymous", "staticTokenFile", "bootstrapTokens", "requestHeader", "externalAuthenticators", "configFile"},
          "SC03 authentication entry")
    require(authn["anonymous"] is False and authn["staticTokenFile"] is None and authn["bootstrapTokens"] is False,
            "SC03 anonymous, static-token and bootstrap-token authentication must be off")
    # A front-proxy client certificate may assert any user and group (system:masters included) in request
    # headers, and an external JWT or webhook authenticator mints identities outside the closure.
    require(authn["requestHeader"] is False and authn["externalAuthenticators"] == [],
            "SC03 request-header and external authenticators must be off")
    require(authn["configFile"] is None or _path(authn["configFile"]), "SC03 authentication configuration file")
    tokens = api["serviceAccountTokens"]
    _keys(tokens, {"signingEndpoint", "signingKeyReaders", "verificationKeys", "verificationKeyIsSigningPublicKey",
                   "issuers", "lookup"}, "SC03 service-account token entry")
    require(tokens["signingEndpoint"] is None, "SC03 no external service-account token signer")
    require(tokens["signingKeyReaders"] == ["APISERVER"], "SC03 service-account signing key readable only by the apiserver")
    # Every verification key is a minting key for whoever holds its private half.
    require(type(tokens["verificationKeys"]) is int and tokens["verificationKeys"] == 1
            and tokens["verificationKeyIsSigningPublicKey"] is True,
            "SC03 the only service-account verification key is the public half of the apiserver's signing key")
    require(type(tokens["issuers"]) is list and len(tokens["issuers"]) == 1 and _text(tokens["issuers"][0]),
            "SC03 exactly one fixed service-account issuer")
    require(tokens["lookup"] is True, "SC03 service-account token lookup must stay on")
    authz = api["authorization"]
    _keys(authz, {"source", "authorizers"}, "SC04 authorization entry")
    require(authz["source"] == "AUTHORIZATION_CONFIG_FILE" and authz["authorizers"] == ["Node", "RBAC"],
            "SC04 authorization must be exactly Node then RBAC from a sealed structured configuration file")
    plugins = api["admissionPlugins"]
    _keys(plugins, {"enabled"}, "SC05 admission entry")
    enabled = plugins["enabled"]
    require(type(enabled) is list and all(type(name) is str for name in enabled) and len(set(enabled)) == len(enabled),
            "SC05 admission plugin list")
    require(all(name in enabled for name in REQUIRED_ADMISSION), "SC05 required admission plugin missing")
    require(not set(enabled) & set(FORBIDDEN_ADMISSION), "SC05 forbidden admission plugin enabled")
    require(set(enabled) <= set(ALLOWED_ADMISSION), "SC05 admission plugin outside the allowed set")
    require(api["admissionManifestsDir"] is None or _path(api["admissionManifestsDir"]), "SC12 admission manifests directory")
    require(api["auditPolicyFile"] is None or _path(api["auditPolicyFile"]), "SC12 audit policy file")
    require(api["apiServices"] == "LOCAL_ONLY" and api["customResourceDefinitions"] == [],
            "SC09 only local APIServices and no CustomResourceDefinitions")

    cm = record["controllerManager"]
    _keys(cm, {"useServiceAccountCredentials", "controllers", "clusterSigning", "serviceAccountPrivateKeyFile"},
          "SC06 controller-manager entry")
    require(cm["useServiceAccountCredentials"] is True, "SC06 per-controller service-account credentials required")
    require(cm["clusterSigning"] is None and cm["serviceAccountPrivateKeyFile"] is None,
            "SC06 controller-manager holds no signing key")
    known = {row["name"]: row for row in inventory["controllers"]}
    running = cm["controllers"]
    require(type(running) is list and all(type(name) is str for name in running) and len(set(running)) == len(running)
            and set(running) <= set(known), "SC06 controller unknown to the v1.37 inventory")
    require(not [name for name in running if known[name]["profile"] == "REQUIRED_DISABLED"],
            "SC06 required-disabled controller enabled")

    kubelet = record["kubelet"]
    _keys(kubelet, {"rotateCertificates", "serverTLSBootstrap", "staticPodPath", "staticPodURL", "staticPodURLHeader",
                    "anonymousAuth", "readOnlyPort", "authorizationMode"}, "SC07 kubelet entry")
    require(kubelet["rotateCertificates"] is False and kubelet["serverTLSBootstrap"] is False,
            "SC07 kubelet certificate rotation and TLS bootstrap must be off")
    require(kubelet["staticPodPath"] is None and kubelet["staticPodURL"] is None and kubelet["staticPodURLHeader"] == {},
            "SC07 kubelet must have no static pod source (file or URL)")
    require(kubelet["anonymousAuth"] is False and _zero(kubelet["readOnlyPort"]) and kubelet["authorizationMode"] == "Webhook",
            "SC07 kubelet must have no anonymous or read-only access, and Webhook authorization")

    versioning = record["versioning"]
    _keys(versioning, {"emulatedVersion", "minCompatibilityVersion", "runtimeConfig", "featureGates"}, "SC15 versioning entry")
    require(versioning["emulatedVersion"] is None and versioning["minCompatibilityVersion"] is None
            and versioning["runtimeConfig"] == {},
            "SC15 emulated and minimum-compatibility versions keep their defaults and runtime-config is empty")
    gated = sorted(name for name in GATED_COMPONENTS if name in keys)
    gates = versioning["featureGates"]
    require(type(gates) is dict and sorted(gates) == gated and all(gates[name] == {} for name in gated),
            "SC15 feature gates must keep their v1.37 defaults in every component")
    creds = record["credentialsOnHost"]
    _keys(creds, {"clusterAdminCredentials", "trustedCaPrivateKeys", "bootstrapTokens"}, "SC03 credential census")
    require(all(_zero(creds[key]) for key in creds),
            "SC03 no cluster-admin credential, trusted CA private key or bootstrap token on the host")
    clients = record["apiClients"]
    _keys(clients, {"automountedTokens", "identities"}, "SC10 API clients")
    allowed = {API_CLIENTS[name] for name in API_CLIENTS if name in keys}
    require(clients["automountedTokens"] is False and type(clients["identities"]) is list
            and all(type(name) is str for name in clients["identities"])
            and len(set(clients["identities"])) == len(clients["identities"]) and set(clients["identities"]) <= allowed,
            "SC10 API client outside the closure's component identities")
    socket = record["runtimeSocket"]
    _keys(socket, {"path", "allowedClientType"}, "SC11 runtime socket")
    require(_path(socket["path"]) and socket["allowedClientType"] == COMPONENT_TYPES["KUBELET"],
            "SC11 runtime socket reachable beyond the kubelet")
    sealed = record["sealedConfiguration"]
    _keys(sealed, {"files", "autoApplyManifestDirs"}, "SC12 sealed configuration")
    expected = set(SEALED_FILES) | {name for name, used in (
        ("ADMISSION_MANIFESTS", api["admissionManifestsDir"] is not None), ("AUDIT_CONFIG", api["auditPolicyFile"] is not None),
        ("AUTHENTICATION_CONFIG", authn["configFile"] is not None),
        ("NETWORK_POLICY_AGENT_CONFIG", "NETWORK_POLICY_AGENT" in keys), ("SERVICE_PROXY_CONFIG", "SERVICE_PROXY" in keys)) if used}
    files = sealed["files"]
    require(type(files) is list and len(set(files)) == len(files) and set(files) == expected,
            "SC12 sealed configuration must be exactly the profile's file set")
    dirs = sealed["autoApplyManifestDirs"]
    require(type(dirs) is list, "SC12 auto-apply manifest directories")
    for row in dirs:
        _keys(row, {"path", "empty", "sealed"}, "SC12 auto-apply manifest directory entry")
        require(_path(row["path"]) and row["empty"] is True and row["sealed"] is True,
                "SC12 auto-apply manifest directories must be empty and sealed")
    require(len({row["path"] for row in dirs}) == len(dirs), "SC12 auto-apply manifest directories")


# ---------------------------------------------------------------- RBAC snapshot

def check_rbac_snapshot(snapshot: Any, closure: dict, inventory: dict, bootstrap: Any, namespace: str) -> None:
    """Every subject holding a policy-relevant grant must be a present closure identity, within its entry;
    an absent controller account may carry only its own bootstrap grants."""
    require(type(namespace) is str and DNS_LABEL.fullmatch(namespace) is not None and namespace not in SYSTEM_NAMESPACES,
            "IC00 qualification namespace must be a dedicated namespace")
    _keys(snapshot, {"schemaVersion", "subjects"}, "IC00 closed RBAC snapshot")
    require(snapshot["schemaVersion"] == SNAPSHOT_VERSION and type(snapshot["subjects"]) is list, "IC00 snapshot version")
    entries = {(row["kind"], row["name"]): row for row in closure["identities"]}
    accounts, _ = _controller_accounts(inventory)
    upstream, _ = upstream_rules(bootstrap)
    seen = set()
    for subject in snapshot["subjects"]:
        _keys(subject, {"kind", "name", "exists", "effectiveRules"}, "IC00 closed subject")
        require(subject["kind"] in ("User", "Group", "ServiceAccount") and _text(subject["name"])
                and type(subject["exists"]) is bool and type(subject["effectiveRules"]) is list, "IC00 subject")
        require((subject["kind"] == "ServiceAccount") == subject["name"].startswith(SA_PREFIX),
                "IC00 service-account usernames must use kind ServiceAccount")
        require(subject["kind"] == "ServiceAccount" or subject["exists"] is True, "IC00 only service accounts can be absent")
        key = (subject["kind"], subject["name"])
        require(key not in seen, "IC00 duplicate subject")
        seen.add(key)
        for rule in subject["effectiveRules"]:
            _rule(rule, "IC00 closed rule")
        grants = set()
        for rule in subject["effectiveRules"]:
            grants |= _grants(rule)
        if not grants:
            continue
        entry = entries.get(key)
        if subject["kind"] == "ServiceAccount" and subject["exists"] is False and subject["name"] in accounts:
            # Dormant bootstrap binding: the controller-manager creates accounts only for controllers it starts.
            baseline = derive_grants(upstream.get(key, []))
            require(all(_allowed(grant, baseline, namespace)
                        and (entry is None or _allowed(grant, entry["allowedGrants"], namespace)) for grant in grants),
                    "IC02 absent controller account with grants beyond its bootstrap role: " + subject["name"])
            continue
        require(entry is not None, "IC01 subject with policy-relevant grants outside the identity closure: " + subject["name"])
        require(subject["exists"] is True, "IC02 closure identity not present: " + subject["name"])
        for grant in sorted(grants):
            require(_allowed(grant, entry["allowedGrants"], namespace),
                    "IC03 grant beyond the closure entry: %s %s %s %s at %s" % (subject["name"], grant[0], grant[2], grant[1], grant[3]))
        names = entry["resourceNames"]
        if names is not None:
            for rule in subject["effectiveRules"]:
                if any(g[0] == "SPECIAL" and g[2] in ("escalate", "bind", "*") for g in _grants(rule)):
                    require(rule["resourceNames"] != [] and set(rule["resourceNames"]) <= set(names),
                            "IC04 escalate or bind beyond the named planeon roles: " + subject["name"])
    for key, entry in sorted(entries.items()):
        if entry["mustBePresent"] is True:
            require(key in seen, "IC05 required closure identity absent from the snapshot: " + key[1])


ERRORS = (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError)


def explain(check: Any, *args: Any) -> str | None:
    try:
        check(*args)
    except ERRORS as exc:
        return str(exc) if type(exc) is ValueError else type(exc).__name__
    return None
