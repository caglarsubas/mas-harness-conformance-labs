#!/usr/bin/env python3
"""POLICY-ADMISSION-SEMANTICS/v3 and the A2 admission field allowlists (W02-ADM-F).

The W02-ADM-F successor of `admission_semantics_v2` (adopted and frozen). The sealed A2 objects and their
manifest file are unchanged byte for byte; v3 answers the v2 round-2 findings R2-F1..F5: two more manifest
constraints (MC39, MC40), the env reference defaults as allowed fixed deltas, signer evidence for
disabled-gate fields (C27) and for A1's scope, deadline and stamp (C12), and corrected wording.

DATA_CHECK_ONLY reference model for the A2 in-chain persist check of HOST-INTERFACE-DRAFT-002 section 3.2,
as the owner decided on 2026-10-08: the A2 ValidatingAdmissionPolicy objects live in a sealed admission
manifest directory (static policies, run-independent), not in API objects written through I07.

Upstream facts (Kubernetes v1.37.1): the policy sees only the decoded final object (`object`), never the
request bytes, and its CEL environment has no hash. So A2 cannot compare the final object with the signed
manifest directly. It proves "final object = submitted manifest + allowlisted server deltas" together with
A1, which admitted the exact signed manifest bytes:
- every mutation an enabled in-tree mutator can make on CREATE (scheme defaulting, the request handler,
  BeforeCreate, Service allocation and the W02g-allowlisted admission plugins) is either an allowlisted
  server delta with the value A2 checks, or ruled out by a manifest constraint; A2 re-checks some
  constraints on the final object, and the signer alone guarantees the others (A1's bytes), as the
  allowlists' constraintCoverage table says for each code;
- each signed Pod carries a shape echo (container names and images, init containers, volume names) as
  annotations; A1 proves the echo is the signed one, and A2 compares it with the final object, so an added
  container, volume or changed image fails even though no enabled mutator makes such a change.

- `check_manifest` applies the manifest constraints a signed qualification manifest must meet.
- `final_object` derives the object the policy sees from a manifest and the cluster facts that enabled
  mutators read (defaulting, the ServiceAccount, DefaultTolerationSeconds, Priority, LimitRanger,
  RuntimeClass, PodTopologyLabels and AlwaysPullImages plugins, Service allocation).
- `check_final` is the reference reading of the A2 CEL validations; `a2_objects` renders the static
  ValidatingAdmissionPolicy and binding objects themselves, and `manifest_directory_hash` the loader hash
  the apiserver reports for the sealed directory.
- `check_claim` decides which consumer claims POLICY-ADMISSION-SEMANTICS/v3 supports; the v1 pre-commit
  sentence is met by no boundary, and a v2 claim lacks the evidence v3 asks for.

Nothing here contacts an apiserver, compiles CEL or grants authority.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from typing import Any

SEMANTICS_V1 = "POLICY-ADMISSION-SEMANTICS/v1"
SEMANTICS_V2 = "POLICY-ADMISSION-SEMANTICS/v2"
SEMANTICS_V3 = "POLICY-ADMISSION-SEMANTICS/v3"
KINDS = ("Pod", "ConfigMap", "Service")
STATIC_SUFFIX = ".static.k8s.io"
POLICY_NAMES = {"Pod": "planeon-a2-pod" + STATIC_SUFFIX, "ConfigMap": "planeon-a2-configmap" + STATIC_SUFFIX,
                "Service": "planeon-a2-service" + STATIC_SUFFIX}
GUARD_NAME = "planeon-a2-admission-objects" + STATIC_SUFFIX
BINDING_SUFFIX = "-binding"
MANIFEST_FILE = "planeon-a2.json"
ECHO = {"containers": "planeon.ai/a2-containers", "initContainers": "planeon.ai/a2-init-containers",
        "volumes": "planeon.ai/a2-volumes"}
NOT_READY, UNREACHABLE = "node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"
# The one non-gate creator of a matched kind in the qualification namespace (W01 section 2.5): the root-CA publisher
# of kube-controller-manager, under its per-controller service account (W02g SC06 requires per-controller credentials).
PUBLISHER_CONFIGMAP = "kube-root-ca.crt"
PUBLISHER_USER = "system:serviceaccount:kube-system:root-ca-cert-publisher"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
# Label and annotation keys in a Kubernetes-reserved prefix (kubernetes.io, k8s.io and their subdomains).
RESERVED_KEY = re.compile(r"^([^/]*\.)?(kubernetes|k8s)\.io/")
DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
DIGEST_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
ADMISSION_RESOURCES = ("validatingadmissionpolicies", "validatingadmissionpolicybindings",
                       "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
                       "validatingwebhookconfigurations", "mutatingwebhookconfigurations")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- manifest constraints

VOLUME_SOURCES = ("emptyDir", "configMap", "secret", "downwardAPI", "projected")   # MC41: their defaults are modelled
PROJECTED_SOURCES = ("configMap", "secret", "downwardAPI")
POD_SPEC_FORBIDDEN = ("nodeName", "nodeSelector", "runtimeClassName", "overhead", "priority", "priorityClassName",
                      "preemptionPolicy", "tolerations", "imagePullSecrets", "ephemeralContainers", "schedulingGates",
                      "resourceClaims", "hostNetwork", "hostPID", "hostIPC", "hostUsers", "serviceAccount")
META_FORBIDDEN = ("generateName", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp",
                  "deletionGracePeriodSeconds", "managedFields", "ownerReferences", "finalizers", "selfLink")
SERVICE_FORBIDDEN = ("clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy", "externalIPs", "externalName",
                     "loadBalancerIP", "loadBalancerSourceRanges", "loadBalancerClass", "externalTrafficPolicy",
                     "healthCheckNodePort", "allocateLoadBalancerNodePorts", "sessionAffinityConfig", "trafficDistribution")


def echo_value(entries: list | None, field: str) -> str:
    if not entries:
        return ""
    if field == "volumes":
        return ",".join(v["name"] for v in entries)
    return ",".join("%s=%s" % (c["name"], c["image"]) for c in entries)


def check_manifest(kind: str, manifest: Any, namespace: str) -> str | None:
    """None when the signed manifest meets the qualification constraints; otherwise the refusal code."""
    if type(manifest) is not dict or manifest.get("apiVersion") != "v1" or manifest.get("kind") != kind or kind not in KINDS:
        return "MC00 not a v1 manifest of a qualification kind"
    meta = manifest.get("metadata")
    if kind == "ConfigMap" and type(meta) is dict and meta.get("name") == PUBLISHER_CONFIGMAP:
        return "MC11 the root-CA publisher's ConfigMap name is reserved"
    if type(meta) is not dict or type(meta.get("name")) is not str or not DNS_LABEL.match(meta["name"]):
        return "MC01 an explicit DNS-label name is required"
    if meta.get("namespace") != namespace:
        return "MC02 the explicit qualification namespace is required"
    if any(key in meta for key in META_FORBIDDEN):
        return "MC03 server-populated or ownership metadata in the manifest"
    for field in ("labels", "annotations"):
        if any(RESERVED_KEY.match(key) for key in (meta.get(field) or {})):
            return "MC04 a label or annotation key in a Kubernetes-reserved prefix"
    if "status" in manifest:
        return "MC05 status in the manifest"
    if kind == "ConfigMap":
        return None if manifest.get("immutable") is True else "MC10 a ConfigMap must be immutable"
    spec = manifest.get("spec")
    if type(spec) is not dict:
        return "MC06 spec required"
    if kind == "Service":
        if spec.get("type") != "ClusterIP":
            return "MC20 an explicit type ClusterIP is required"
        if any(key in spec for key in SERVICE_FORBIDDEN) or any("nodePort" in port for port in spec.get("ports", [])):
            return "MC21 an allocated, external or load-balancer field in a ClusterIP Service"
        if spec.get("sessionAffinity", "None") != "None" or spec.get("internalTrafficPolicy", "Cluster") != "Cluster":
            return "MC22 session affinity or traffic policy other than the defaults"
        return None
    if any(key in spec for key in POD_SPEC_FORBIDDEN):
        return "MC30 a field an enabled mutator reads or sets (node, runtime class, priority, tolerations, pull secrets, host namespaces)"
    if spec.get("automountServiceAccountToken") is not False:
        return "MC31 automountServiceAccountToken must be false"
    containers, inits = spec.get("containers") or [], spec.get("initContainers") or []
    if not containers:
        return "MC32 at least one container"
    for c in containers + inits:
        if not DIGEST_IMAGE.match(c.get("image", "")) or c.get("imagePullPolicy") != "Always":
            return "MC33 every image is pinned by digest and pulled Always"
        resources = c.get("resources") or {}
        if not resources.get("limits") or resources.get("requests") != resources.get("limits"):
            return "MC34 every container states equal requests and limits"
        if any(m.get("mountPath", "").startswith(TOKEN_PATH) for m in c.get("volumeMounts", [])):
            return "MC35 a mount at the service-account token path"
    names = [v["name"] for v in spec.get("volumes") or []]
    if any(name.startswith("kube-api-access-") for name in names):
        return "MC36 a volume named like the service-account token volume"
    if any("image" in v for v in spec.get("volumes") or []):
        return "MC38 an image volume (AlwaysPullImages rewrites its pull policy)"
    if "resources" in spec:
        return "MC39 pod-level resources (DefaultPodLevelResources fills pod-level requests, limits and hugepage limits)"
    if "affinity" in spec or "topologySpreadConstraints" in spec:
        return "MC40 affinity or topology spread constraints (matchLabelKeys merge into their selectors)"
    for v in spec.get("volumes") or []:
        sources = set(v) - {"name"}
        if len(sources) != 1 or not sources <= set(VOLUME_SOURCES) or (
                "projected" in v and any(len(src) != 1 or not set(src) <= set(PROJECTED_SOURCES)
                                         for src in (v["projected"].get("sources") or []))):
            return "MC41 a volume source outside emptyDir, configMap, secret, downwardAPI and projected (configMap, secret, downwardAPI)"
    annotations = meta.get("annotations") or {}
    for field, key in ECHO.items():
        if annotations.get(key) != echo_value(spec.get(field), field):
            return "MC37 the shape echo annotation does not match the manifest: " + key
    return None


# ---------------------------------------------------------------- the object the policy sees

def _quantity(value: str) -> str:
    """The canonical form the apiserver re-emits for the quantities the vectors use."""
    if value.endswith("Gi") and "." in value:
        return "%dMi" % round(float(value[:-2]) * 1024)
    return value


def final_object(kind: str, manifest: dict, server: dict) -> dict:
    """The CREATE object as the A2 policy sees it: scheme defaulting, the request handler, BeforeCreate,
    Service allocation and the enabled mutating admission plugins, each acting as upstream v1.37.1 does
    for the given cluster facts. resourceVersion is set only after the policy and is absent here."""
    obj = copy.deepcopy(manifest)
    meta = obj.setdefault("metadata", {})
    for key in ("uid", "creationTimestamp", "selfLink", "deletionTimestamp", "deletionGracePeriodSeconds"):
        meta.pop(key, None)
    meta.setdefault("namespace", server["namespace"])
    meta.update(uid=server["uid"], creationTimestamp=server["creationTimestamp"],
                managedFields=[{"manager": server["fieldManager"], "operation": "Update", "apiVersion": "v1",
                                "time": server["creationTimestamp"], "fieldsType": "FieldsV1"}])
    if kind == "ConfigMap":
        if not obj.get("data"):
            obj.pop("data", None)                   # defaulted to {}, omitted in the policy's view
        return obj
    spec = obj.setdefault("spec", {})
    if kind == "Service":
        spec.setdefault("type", "ClusterIP")
        spec.setdefault("sessionAffinity", "None")
        spec.setdefault("internalTrafficPolicy", "Cluster")
        for port in spec.get("ports", []):
            port.setdefault("protocol", "TCP")
            port.setdefault("targetPort", port["port"])
        spec.setdefault("ipFamilyPolicy", "SingleStack")
        spec.setdefault("ipFamilies", [server["ipFamily"]])
        if "clusterIP" not in spec:
            spec["clusterIP"] = server["clusterIP"]
        spec.setdefault("clusterIPs", [spec["clusterIP"]])
        obj["status"] = {"loadBalancer": {}}
        return obj
    # Pod: scheme defaulting.
    for key, value in (("dnsPolicy", "ClusterFirst"), ("restartPolicy", "Always"), ("securityContext", {}),
                       ("terminationGracePeriodSeconds", 30), ("schedulerName", "default-scheduler"),
                       ("enableServiceLinks", True)):
        spec.setdefault(key, value)
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        c.setdefault("terminationMessagePath", "/dev/termination-log")
        c.setdefault("terminationMessagePolicy", "File")
        c.setdefault("imagePullPolicy", "Always" if ":" not in c.get("image", "").split("/")[-1] or
                     c["image"].endswith(":latest") else "IfNotPresent")
        for port in c.get("ports", []):
            port.setdefault("protocol", "TCP")
        for env in c.get("env", []):
            source = env.get("valueFrom") or {}
            if "fieldRef" in source:
                source["fieldRef"].setdefault("apiVersion", "v1")       # core/v1/defaults.go:397-401 SetDefaults_ObjectFieldSelector
            if "fileKeyRef" in source:
                source["fileKeyRef"].setdefault("optional", False)      # generated inline: core/v1/zz_generated.defaults.go:312-316, 386-390
        resources = c.get("resources")
        if resources:
            for section in ("limits", "requests"):
                if section in resources:
                    resources[section] = {k: _quantity(v) for k, v in resources[section].items()}
            for key, value in resources.get("limits", {}).items():
                resources.setdefault("requests", {}).setdefault(key, value)
    # Volume scheme defaulting (core/v1/defaults.go:289-317, 397-401; zz_generated.defaults.go:234-275) for the MC41 sources.
    for v in spec.get("volumes", []):
        for kind in ("configMap", "secret", "downwardAPI", "projected"):
            if kind in v:
                v[kind].setdefault("defaultMode", 420)
        items = list((v.get("downwardAPI") or {}).get("items", []))
        for src in (v.get("projected") or {}).get("sources", []):
            items += (src.get("downwardAPI") or {}).get("items", [])
        for item in items:
            if "fieldRef" in item:
                item["fieldRef"].setdefault("apiVersion", "v1")
    # ServiceAccount plugin.
    if not spec.get("serviceAccountName"):
        spec["serviceAccountName"] = "default"
    spec["serviceAccount"] = spec["serviceAccountName"]
    automount = spec.get("automountServiceAccountToken", server.get("serviceAccountAutomount", True))
    if automount is not False:
        volume = "kube-api-access-" + server["tokenVolumeSuffix"]
        spec.setdefault("volumes", []).append({"name": volume, "projected": {"defaultMode": 420, "sources": [
            {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}}]}})
        for c in spec.get("containers", []) + spec.get("initContainers", []):
            c.setdefault("volumeMounts", []).append({"name": volume, "readOnly": True, "mountPath": TOKEN_PATH})
    if not spec.get("imagePullSecrets") and server.get("serviceAccountPullSecrets"):
        spec["imagePullSecrets"] = [{"name": name} for name in server["serviceAccountPullSecrets"]]
    # DefaultTolerationSeconds plugin.
    tolerations = spec.setdefault("tolerations", [])
    for key in (NOT_READY, UNREACHABLE):
        if not any(t.get("key") == key and t.get("effect") in (None, "NoExecute") for t in tolerations):
            tolerations.append({"key": key, "operator": "Exists", "effect": "NoExecute",
                                "tolerationSeconds": server["defaultTolerationSeconds"]})
    # Priority plugin.
    default_class = server.get("globalDefaultPriorityClass")
    if "priorityClassName" not in spec and default_class:
        spec["priorityClassName"] = default_class["name"]
    if "priorityClassName" in spec and default_class and spec["priorityClassName"] == default_class["name"]:
        spec["priority"], spec["preemptionPolicy"] = default_class["value"], default_class["preemptionPolicy"]
    else:
        spec.setdefault("priority", 0)
        spec.setdefault("preemptionPolicy", "PreemptLowerPriority")
    # LimitRanger plugin: defaults for resource keys the containers omit, and its annotation.
    limit_defaults = server.get("limitRangeDefaults") or {}
    changed = False
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        resources = c.setdefault("resources", {})
        for key, value in limit_defaults.items():
            if key not in resources.get("limits", {}):
                resources.setdefault("limits", {})[key] = value
                resources.setdefault("requests", {})[key] = value
                changed = True
    if changed:
        meta.setdefault("annotations", {})["kubernetes.io/limit-ranger"] = "LimitRanger plugin set: defaults"
    # RuntimeClass plugin (only with runtimeClassName).
    runtime = (server.get("runtimeClasses") or {}).get(spec.get("runtimeClassName"))
    if runtime and runtime.get("overhead"):
        spec["overhead"] = runtime["overhead"]
    # PodTopologyLabels (only with nodeName).
    if spec.get("nodeName") and server.get("nodeTopologyZone"):
        meta.setdefault("labels", {})["topology.kubernetes.io/zone"] = server["nodeTopologyZone"]
    # AlwaysPullImages (W02g allows it; off by default).
    if server.get("alwaysPullImages"):
        for c in spec.get("containers", []) + spec.get("initContainers", []):
            c["imagePullPolicy"] = "Always"
        for v in spec.get("volumes", []):
            if "image" in v:
                v["image"]["pullPolicy"] = "Always"     # alwayspullimages/admission.go:76-81
    meta["generation"] = 1
    qos = "Guaranteed" if all((c.get("resources") or {}).get("limits") and c["resources"].get("requests") ==
                              c["resources"].get("limits") for c in spec.get("containers", [])) else "Burstable"
    obj["status"] = {"phase": "Pending", "qosClass": qos}
    return obj


# ---------------------------------------------------------------- the A2 validations (reference reading of the CEL)

def _keys_unreserved(meta: dict) -> bool:
    return not any(RESERVED_KEY.match(key) for field in ("labels", "annotations") for key in (meta.get(field) or {}))


def _in_cidr(address: Any, cidr: str) -> bool:
    try:
        return type(address) is str and ipaddress.ip_address(address) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


def check_final(kind: str, obj: dict, sealed: dict, username: str | None = None) -> str | None:
    """None when the static A2 policy for `kind` admits the object created by `username`; otherwise the failing
    validation. Each branch is one validation of `a2_objects`, in order. A field a CEL expression dereferences
    without a has() guard is required: its absence is a runtime error, which failurePolicy Fail denies."""
    meta = obj.get("metadata", {})
    publisher = kind == "ConfigMap" and meta.get("name") == PUBLISHER_CONFIGMAP
    if kind == "ConfigMap" and publisher:
        data = obj.get("data") or {}
        annotations = meta.get("annotations") or {}
        if username != PUBLISHER_USER or set(data) != {"ca.crt"} or obj.get("binaryData") or meta.get("labels") \
                or not set(annotations) <= {"kubernetes.io/description"}:
            return "A2-CM-PUBLISHER the reserved root-CA ConfigMap is not exactly the publisher's"
        return None
    if not _keys_unreserved(meta):
        return "A2-RESERVED a label or annotation key in a Kubernetes-reserved prefix"
    if kind == "ConfigMap":
        return None if obj.get("immutable") is True else "A2-CM-IMMUTABLE the ConfigMap is not immutable"
    spec = obj.get("spec", {})
    if kind == "Service":
        if spec.get("type") != "ClusterIP" or type(spec.get("ports")) is not list or any(key in spec for key in (
                "externalIPs", "externalName", "loadBalancerIP", "loadBalancerSourceRanges", "loadBalancerClass",
                "healthCheckNodePort")) or any("nodePort" in port for port in spec["ports"]):
            return "A2-SVC-TYPE not a plain ClusterIP Service"
        ips = spec.get("clusterIPs") or []
        if spec.get("ipFamilyPolicy") != "SingleStack" or spec.get("ipFamilies") != [sealed["ipFamily"]] or len(ips) != 1 \
                or spec.get("clusterIP") != ips[0] or ips[0] == "None" or not _in_cidr(ips[0], sealed["serviceCIDR"]):
            return "A2-SVC-ALLOCATION the allocation is not one address of the sealed service CIDR"
        if spec.get("sessionAffinity") != "None" or spec.get("internalTrafficPolicy") != "Cluster":
            return "A2-SVC-DEFAULTS session affinity or traffic policy differs from the defaults"
        return None
    annotations = meta.get("annotations") or {}
    for field, key in ECHO.items():
        if key not in annotations or annotations[key] != echo_value(spec.get(field), field):
            return "A2-POD-ECHO the final shape differs from the signed shape echo: " + field
    if spec.get("automountServiceAccountToken") is not False:
        return "A2-POD-TOKEN service-account token automount is not disabled"
    if spec.get("imagePullSecrets"):
        return "A2-POD-PULL-SECRETS pull secrets were added"
    if any("image" in v for v in spec.get("volumes") or []):
        return "A2-POD-IMAGE-VOLUME an image volume"
    tolerations = spec.get("tolerations") or []
    expected = [{"key": key, "operator": "Exists", "effect": "NoExecute",
                 "tolerationSeconds": sealed["defaultTolerationSeconds"]} for key in (NOT_READY, UNREACHABLE)]
    if len(tolerations) != 2 or not all(sum(t == e for t in tolerations) == 1 for e in expected):
        return "A2-POD-TOLERATIONS the tolerations are not exactly the two default ones"
    if type(spec.get("priority")) is not int or spec["priority"] != 0 or spec.get("preemptionPolicy") != "PreemptLowerPriority" \
            or "priorityClassName" in spec:
        return "A2-POD-PRIORITY a priority other than the default"
    if any(key in spec for key in ("runtimeClassName", "overhead", "nodeName", "nodeSelector")):
        return "A2-POD-PLACEMENT a runtime class, overhead or node placement"
    if type(spec.get("containers")) is not list or not all(
            c.get("imagePullPolicy") == "Always" for c in spec["containers"] + spec.get("initContainers", [])):
        return "A2-POD-PULL-POLICY an image pull policy other than Always"
    return None


# ---------------------------------------------------------------- the static policy objects

RESERVED_CEL = ("(!has(object.metadata.labels) || object.metadata.labels.all(k, !k.matches('^([^/]*\\\\.)?(kubernetes|k8s)\\\\.io/'))) && "
                "(!has(object.metadata.annotations) || object.metadata.annotations.all(k, !k.matches('^([^/]*\\\\.)?(kubernetes|k8s)\\\\.io/')))")


def _echo_cel(field: str, key: str) -> str:
    render = "v.name" if field == "volumes" else "v.name + '=' + v.image"
    return ("has(object.metadata.annotations) && '%s' in object.metadata.annotations && "
            "object.metadata.annotations['%s'] == (has(object.spec.%s) ? object.spec.%s.map(v, %s).join(',') : '')"
            % (key, key, field, field, render))


PUBLISHER_CEL = "object.metadata.name == '%s'" % PUBLISHER_CONFIGMAP


def _validations(kind: str, sealed: dict) -> list[dict]:
    rows = []
    if kind == "ConfigMap":
        rows.append(("A2-CM-PUBLISHER",
                     "!(%s) || (request.userInfo.username == '%s' && has(object.data) && object.data.size() == 1 && "
                     "'ca.crt' in object.data && !has(object.binaryData) && !has(object.metadata.labels) && "
                     "(!has(object.metadata.annotations) || object.metadata.annotations.all(k, k == 'kubernetes.io/description')))"
                     % (PUBLISHER_CEL, PUBLISHER_USER)))
        rows += [("A2-RESERVED", "%s || (%s)" % (PUBLISHER_CEL, RESERVED_CEL)),
                 ("A2-CM-IMMUTABLE", "%s || (has(object.immutable) && object.immutable == true)" % PUBLISHER_CEL)]
        return [{"expression": expression, "message": code, "reason": "Forbidden"} for code, expression in rows]
    rows.append(("A2-RESERVED", RESERVED_CEL))
    if kind == "Service":
        rows += [
            ("A2-SVC-TYPE", "object.spec.type == 'ClusterIP' && !has(object.spec.externalIPs) && !has(object.spec.externalName) && "
                            "!has(object.spec.loadBalancerIP) && !has(object.spec.loadBalancerSourceRanges) && "
                            "!has(object.spec.loadBalancerClass) && !has(object.spec.healthCheckNodePort) && "
                            "object.spec.ports.all(p, !has(p.nodePort))"),
            ("A2-SVC-ALLOCATION", "object.spec.ipFamilyPolicy == 'SingleStack' && object.spec.ipFamilies.size() == 1 && "
                                  "object.spec.ipFamilies[0] == '%s' && object.spec.clusterIPs.size() == 1 && "
                                  "object.spec.clusterIP == object.spec.clusterIPs[0] && object.spec.clusterIP != 'None' && "
                                  "cidr('%s').containsIP(object.spec.clusterIP)" % (sealed["ipFamily"], sealed["serviceCIDR"])),
            ("A2-SVC-DEFAULTS", "object.spec.sessionAffinity == 'None' && object.spec.internalTrafficPolicy == 'Cluster'")]
    else:
        tol = ("t.operator == 'Exists' && t.effect == 'NoExecute' && has(t.tolerationSeconds) && "
               "t.tolerationSeconds == %d && !has(t.value)" % sealed["defaultTolerationSeconds"])
        rows += [("A2-POD-ECHO", " && ".join(_echo_cel(field, key) for field, key in ECHO.items())),
                 ("A2-POD-TOKEN", "has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false"),
                 ("A2-POD-PULL-SECRETS", "!has(object.spec.imagePullSecrets) || object.spec.imagePullSecrets.size() == 0"),
                 ("A2-POD-IMAGE-VOLUME", "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.image))"),
                 ("A2-POD-TOLERATIONS", "has(object.spec.tolerations) && object.spec.tolerations.size() == 2 && "
                                        "object.spec.tolerations.exists_one(t, t.key == '%s' && %s) && "
                                        "object.spec.tolerations.exists_one(t, t.key == '%s' && %s)" % (NOT_READY, tol, UNREACHABLE, tol)),
                 ("A2-POD-PRIORITY", "has(object.spec.priority) && object.spec.priority == 0 && has(object.spec.preemptionPolicy) && "
                                     "object.spec.preemptionPolicy == 'PreemptLowerPriority' && !has(object.spec.priorityClassName)"),
                 ("A2-POD-PLACEMENT", "!has(object.spec.runtimeClassName) && !has(object.spec.overhead) && "
                                      "!has(object.spec.nodeName) && !has(object.spec.nodeSelector)"),
                 ("A2-POD-PULL-POLICY", "object.spec.containers.all(c, c.imagePullPolicy == 'Always') && "
                                        "(!has(object.spec.initContainers) || object.spec.initContainers.all(c, c.imagePullPolicy == 'Always'))")]
    return [{"expression": expression, "message": code, "reason": "Forbidden"} for code, expression in rows]


def a2_objects(sealed: dict) -> list[dict]:
    """The static ValidatingAdmissionPolicy and binding objects of the sealed admission manifest directory:
    one policy per qualification kind (CREATE in the qualification namespace) and one guard that denies every
    API write of an admission-policy or webhook object. Static: names end in .static.k8s.io, no paramKind,
    no matchConditions (a false matchCondition skips the policy), failurePolicy Fail, binding action Deny."""
    selector = {"matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In",
                                      "values": [sealed["namespace"]]}]}
    objects = []
    for kind in KINDS:
        name = POLICY_NAMES[kind]
        resource = {"Pod": "pods", "ConfigMap": "configmaps", "Service": "services"}[kind]
        objects.append({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                        "metadata": {"name": name},
                        "spec": {"failurePolicy": "Fail",
                                 "matchConstraints": {"matchPolicy": "Exact", "namespaceSelector": selector,
                                                      "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                         "operations": ["CREATE"], "resources": [resource]}]},
                                 "validations": _validations(kind, sealed)}})
    objects.append({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": GUARD_NAME},
                    "spec": {"failurePolicy": "Fail",
                             "matchConstraints": {"matchPolicy": "Exact",
                                                  "resourceRules": [{"apiGroups": ["admissionregistration.k8s.io"],
                                                                     "apiVersions": ["*"],
                                                                     "operations": ["CREATE", "UPDATE", "DELETE"],
                                                                     "resources": list(ADMISSION_RESOURCES)}]},
                             "validations": [{"expression": "false", "reason": "Forbidden",
                                              "message": "A2-GUARD admission objects are written only through the sealed manifest directory"}]}})
    for policy in list(objects):
        objects.append({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                        "metadata": {"name": policy["metadata"]["name"].replace(STATIC_SUFFIX, BINDING_SUFFIX + STATIC_SUFFIX)},
                        "spec": {"policyName": policy["metadata"]["name"], "validationActions": ["Deny"]}})
    return objects


def manifest_file_bytes(sealed: dict) -> bytes:
    """The one file of the sealed directory: a v1 List of the static objects, canonical JSON."""
    return canonical({"apiVersion": "v1", "kind": "List", "items": a2_objects(sealed)})


def manifest_directory_hash(files: dict[str, bytes]) -> str:
    """The loader's hash of a manifest directory: in file-name order, the content of each non-empty .yaml,
    .yml or .json file followed by one NUL byte (manifest/loader.go LoadFiles)."""
    h = hashlib.sha256()
    data = False
    for name in sorted(files):
        if name.lower().endswith((".yaml", ".yml", ".json")) and files[name]:
            h.update(files[name] + b"\x00")
            data = True
    return "sha256:" + h.hexdigest() if data else ""


def check_a2_objects(objects: list, sealed: dict) -> str | None:
    """Structural rules the sealed directory must meet (the loader enforces the name suffix and no paramKind;
    the rest are this contract's)."""
    policies = [o for o in objects if o.get("kind") == "ValidatingAdmissionPolicy"]
    bindings = [o for o in objects if o.get("kind") == "ValidatingAdmissionPolicyBinding"]
    names = [o["metadata"]["name"] for o in policies + bindings]
    if len(names) != len(set(names)) or not all(n.endswith(STATIC_SUFFIX) for n in names) or len(policies) + len(bindings) != len(objects):
        return "S01 only uniquely named static policies and bindings"
    if {p["metadata"]["name"] for p in policies} != set(POLICY_NAMES.values()) | {GUARD_NAME}:
        return "S02 the closed set of A2 policies"
    for p in policies:
        spec = p["spec"]
        if "paramKind" in spec or "matchConditions" in spec or spec.get("failurePolicy") != "Fail" \
                or spec["matchConstraints"].get("matchPolicy") != "Exact" or "objectSelector" in spec["matchConstraints"] \
                or "excludeResourceRules" in spec["matchConstraints"]:
            return "S03 no paramKind, matchConditions, objectSelector or exclusions; failurePolicy Fail; matchPolicy Exact"
    by_policy = {}
    for b in bindings:
        spec = b["spec"]
        if "paramRef" in spec or "matchResources" in spec or spec.get("validationActions") != ["Deny"]:
            return "S04 every binding denies, with no paramRef or narrowed match"
        by_policy.setdefault(spec.get("policyName"), []).append(b)
    if set(by_policy) != {p["metadata"]["name"] for p in policies} or any(len(v) != 1 for v in by_policy.values()):
        return "S05 exactly one binding per policy"
    expected = a2_objects(sealed)
    if objects != expected:
        return "S06 the objects differ from the contract's rendering for the sealed values"
    return None


# ---------------------------------------------------------------- POLICY-ADMISSION-SEMANTICS claims

CHECKS = ("A1", "A2", "A3", "A4")


def check_claim(claim: Any, pinned: dict) -> str | None:
    """None when POLICY-ADMISSION-SEMANTICS/v3 supports the consumer's claim; otherwise why not.
    `pinned` carries the sealed manifest-directory hash and the qualification namespace the A2 policies match."""
    if type(claim) is not dict:
        return "C00 not a claim"
    if claim.get("semantics") == SEMANTICS_V1:
        return "C01 the v1 pre-commit recheck sentence is met by no boundary; cite POLICY-ADMISSION-SEMANTICS/v3 checks"
    if claim.get("semantics") == SEMANTICS_V2:
        return "C03 a v2 claim lacks the A1 scope, deadline and stamp evidence and the disabled-gate evidence; cite v3"
    if claim.get("semantics") != SEMANTICS_V3 or claim.get("check") not in CHECKS:
        return "C02 unknown semantics version or check"
    evidence = claim.get("evidence") or {}
    check = claim["check"]
    if check == "A1":
        if claim.get("boundary") != "EFFECT_GATE":
            return "C10 A1 is the gate's pre-forward linearization point; no other boundary admits"
        if not (evidence.get("consumedRecordDurableBeforeFirstByte") is True and evidence.get("generationActive") is True
                and evidence.get("observedPolicyGenerationCurrent") is True and evidence.get("requestBytesEqualRendering") is True):
            return "C11 A1 needs the durable consumption before the first byte, an ACTIVE generation, the current policy generation and the exact rendering"
        if not (evidence.get("executionBoundAndUnexpired") is True and evidence.get("runCertificateMatched") is True
                and evidence.get("stampEqualsArmedAction") is True):
            return "C12 A1 also needs its scope and deadline (the bound, unexpired execution and its run certificate) and the stamp equal to the armed action"
        return None
    if check == "A2":
        if claim.get("boundary") != "APISERVER_VALIDATING_ADMISSION":
            return "C20 A2 runs inside the sealed apiserver after mutating admission and before persistence"
        if evidence.get("loadedManifestHash") != pinned["manifestDirectoryHash"]:
            return "C21 the loaded static manifest hash is not the sealed directory's"
        if evidence.get("webhookAndMutatingPolicyObjectsAbsent") is not True or evidence.get("admissionPluginsWithinAllowlist") is not True:
            return "C22 A2's allowlist argument needs no webhook or mutating-policy objects and only allowlisted admission plugins (W02g OR06, SC05)"
        if evidence.get("a1AdmittedSignedBytes") is not True:
            return "C23 A2 proves final = submitted + allowlisted deltas only together with A1's byte check"
        if evidence.get("manifestConstraintsMetAtSigning") is not True:
            return "C25 the signed manifests met check_manifest at signing; A2 re-checks only part of the constraints"
        if evidence.get("disabledGateFieldsAbsentAtSigning") is not True:
            return "C27 the signed manifests carry no field of a feature gate the sealed apiserver disables (check_manifest alone does not cover it)"
        if evidence.get("namespace") != pinned["namespace"]:
            return "C26 A2 covers only the sealed qualification namespace"
        if evidence.get("claimsByteEquality") is True:
            return "C24 A2 never compares bytes; it checks the final object's fields"
        return None
    if check == "A3":
        if claim.get("boundary") != "I07_WRITE":
            return "C30 A3 is the fence before an I07 policy write"
        if evidence.get("drainAnswer") != "OPEN" or evidence.get("everyConsumedActionTerminal") is not True:
            return "C31 A3 needs the I05 drain answer OPEN: no consumed action without a durable terminal classification"
        return None
    if evidence.get("claimsStrictOrdering") is True:
        return "C40 A4 is explicitly weaker: an admitted action may persist after the invalidating change"
    if evidence.get("admittedBeforeInvalidationRecorded") is not True:
        return "C41 A4 needs ADMITTED_BEFORE_INVALIDATION recorded with the terminal or ambiguous outcome"
    return None
