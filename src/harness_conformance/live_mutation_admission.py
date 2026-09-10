"""Closed proxy admission data and durable bookkeeping; data never grants execution.

Authority: MET-REPAIR-009/010/013/014/015. Native owners must independently establish
custody, current policy and the capacity broker's transactional generation fence.
No import-time I/O, generic Kubernetes client, callback or environment backend.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import re
from types import MappingProxyType

from .canonical import byte_digest, canonical_bytes, canonical_digest, require_canonical_document
from .errors import ConformanceError
from .linux_readiness import CASES, require_time
from .schema import closed, require_digest

PROFILE_PATH = "campaigns/platform/linux-baseline/proxy-profile.json"
OBSERVATION_PATH = "campaigns/platform/linux-baseline/policy-observation-binding.json"
POLICIES = ("admissionPolicy", "resourceQuota", "limitRange", "serviceAccount", "rbac", "networkPolicy", "mutationBroker")
PATHS = ["/v1/linux-baseline/" + case.lower().replace("_", "-") for case in CASES]
ZERO = "sha256:" + "0" * 64
UNITS = ("pods", "configMaps", "services", "cpuMillis", "memoryBytes", "ephemeralStorageBytes")
# Immutable private specification, not a runtime-provided schema or authority.
_PROFILE_SPEC = json.loads("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"https://schemas.planeon.ai/internal/proxy-execution-profile/v1.json\",\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"profileId\",\"binding\",\"capacityEntries\",\"policy\",\"quota\",\"resources\",\"localImages\"],\"properties\":{\"profileId\":{\"const\":\"CAMPAIGN_PROXY_MTLS_ZERO_COST_V1\"},\"binding\":{\"$ref\":\"#/$defs/binding\"},\"capacityEntries\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"kubernetesApiRules\",\"campaignProxyRules\",\"permittedGvksAndVerbs\",\"preexistingResourceRefs\",\"preallocatedStorageRefs\",\"preallocatedAcceleratorRefs\",\"credentialIdentities\"],\"properties\":{\"kubernetesApiRules\":{\"type\":\"array\",\"minItems\":0,\"maxItems\":256,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/apiRule\"}},\"campaignProxyRules\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":1,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/proxyRule\"}},\"permittedGvksAndVerbs\":{\"type\":\"array\",\"minItems\":0,\"maxItems\":3,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/gvkRule\"}},\"preexistingResourceRefs\":{\"type\":\"array\",\"minItems\":0,\"maxItems\":256,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/resourceRef\"}},\"preallocatedStorageRefs\":{\"type\":\"array\",\"maxItems\":0},\"preallocatedAcceleratorRefs\":{\"type\":\"array\",\"maxItems\":0},\"credentialIdentities\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":2,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/credentialIdentity\"}}}},\"policy\":{\"$ref\":\"#/$defs/policy\"},\"quota\":{\"$ref\":\"#/$defs/units\"},\"resources\":{\"type\":\"array\",\"minItems\":0,\"maxItems\":32,\"uniqueItems\":true,\"items\":{\"$ref\":\"#/$defs/resource\"}},\"localImages\":{\"type\":\"array\",\"minItems\":0,\"maxItems\":16,\"uniqueItems\":true,\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":1024,\"pattern\":\"^[a-z0-9][a-z0-9.:/-]*@sha256:[0-9a-f]{64}$\"}}},\"$defs\":{\"binding\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"tenantId\",\"environmentId\",\"runNonce\",\"capacityNonce\",\"endpointId\",\"namespace\",\"serviceAccountSubject\",\"validFrom\",\"expiresAt\",\"apiEndpointId\"],\"properties\":{\"tenantId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"environmentId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"capacityNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"serviceAccountSubject\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$\"},\"validFrom\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}Z$\"},\"expiresAt\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}Z$\"},\"apiEndpointId\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},{\"type\":\"null\"}]}}},\"credentialIdentity\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"endpointId\",\"purpose\",\"subject\",\"expiresAt\",\"certificateDigest\",\"clientSpkiDigest\"],\"properties\":{\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"purpose\":{\"enum\":[\"CAMPAIGN_PROXY_CLIENT_MTLS\",\"KUBERNETES_PROXY_SERVER_MTLS\"]},\"subject\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$\"},\"expiresAt\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^\\\\d{4}-\\\\d{2}-\\\\d{2}T\\\\d{2}:\\\\d{2}:\\\\d{2}Z$\"},\"certificateDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"clientSpkiDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"apiRule\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"endpointId\",\"verb\",\"apiGroup\",\"apiVersion\",\"resource\",\"namespace\",\"name\",\"subresource\",\"requestMediaType\",\"responseMediaType\",\"requestMaxBytes\",\"responseMaxBytes\"],\"properties\":{\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"verb\":{\"enum\":[\"get\",\"create\",\"delete\"]},\"apiGroup\":{\"const\":\"\"},\"apiVersion\":{\"const\":\"v1\"},\"resource\":{\"enum\":[\"pods\",\"configmaps\",\"services\"]},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"subresource\":{\"const\":\"\"},\"requestMediaType\":{\"const\":\"application/json\"},\"responseMediaType\":{\"const\":\"application/json\"},\"requestMaxBytes\":{\"const\":16384},\"responseMaxBytes\":{\"const\":4194304}}},\"proxyRule\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"endpointId\",\"namespace\",\"service\",\"port\",\"protocol\",\"methods\",\"paths\",\"requestMediaType\",\"responseMediaType\",\"requestMaxBytes\",\"responseMaxBytes\",\"timeoutSeconds\"],\"properties\":{\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"service\":{\"const\":\"linux-baseline-probes\"},\"port\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535},\"protocol\":{\"const\":\"HTTPS\"},\"methods\":{\"const\":[\"POST\"]},\"paths\":{\"type\":\"array\",\"minItems\":10,\"maxItems\":10,\"uniqueItems\":true,\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^/v1/linux-baseline/[a-z-]+$\"}},\"requestMediaType\":{\"const\":\"application/json\"},\"responseMediaType\":{\"const\":\"application/json\"},\"requestMaxBytes\":{\"const\":16384},\"responseMaxBytes\":{\"const\":4194304},\"timeoutSeconds\":{\"const\":900}}},\"gvkRule\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiGroup\",\"apiVersion\",\"kind\",\"verbs\",\"names\"],\"properties\":{\"apiGroup\":{\"const\":\"\"},\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"enum\":[\"Pod\",\"ConfigMap\",\"Service\"]},\"verbs\":{\"const\":[\"create\",\"get\",\"delete\"]},\"names\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":32,\"uniqueItems\":true,\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"}}}},\"resourceRef\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"namespace\",\"name\",\"uid\",\"observedDigest\"],\"properties\":{\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"enum\":[\"ResourceQuota\",\"LimitRange\",\"ServiceAccount\",\"Service\",\"ConfigMap\"]},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-zA-Z0-9-]{1,128}$\"},\"observedDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"units\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"pods\",\"configMaps\",\"services\",\"cpuMillis\",\"memoryBytes\",\"ephemeralStorageBytes\"],\"properties\":{\"pods\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"configMaps\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"services\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"cpuMillis\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"memoryBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"ephemeralStorageBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991}}},\"manifest\":{\"oneOf\":[{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"metadata\",\"spec\"],\"properties\":{\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"const\":\"Pod\"},\"metadata\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"namespace\",\"labels\"],\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"labels\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"planeon.ai/run-nonce\",\"planeon.ai/tenant-id\"],\"properties\":{\"planeon.ai/run-nonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"planeon.ai/tenant-id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"}}}}},\"spec\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"restartPolicy\",\"serviceAccountName\",\"automountServiceAccountToken\",\"enableServiceLinks\",\"hostNetwork\",\"hostPID\",\"hostIPC\",\"containers\"],\"properties\":{\"restartPolicy\":{\"const\":\"Never\"},\"serviceAccountName\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"automountServiceAccountToken\":{\"const\":false},\"enableServiceLinks\":{\"const\":false},\"hostNetwork\":{\"const\":false},\"hostPID\":{\"const\":false},\"hostIPC\":{\"const\":false},\"containers\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":1,\"items\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"image\",\"imagePullPolicy\",\"resources\",\"securityContext\"],\"properties\":{\"name\":{\"const\":\"probe\"},\"image\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":1024,\"pattern\":\"^[a-z0-9][a-z0-9.:/-]*@sha256:[0-9a-f]{64}$\"},\"imagePullPolicy\":{\"const\":\"Never\"},\"resources\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"requests\",\"limits\"],\"properties\":{\"requests\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"cpu\",\"memory\",\"ephemeral-storage\"],\"properties\":{\"cpu\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,6}m$\"},\"memory\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,14}$\"},\"ephemeral-storage\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,14}$\"}}},\"limits\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"cpu\",\"memory\",\"ephemeral-storage\"],\"properties\":{\"cpu\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,6}m$\"},\"memory\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,14}$\"},\"ephemeral-storage\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[1-9][0-9]{0,14}$\"}}}}},\"securityContext\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"allowPrivilegeEscalation\",\"readOnlyRootFilesystem\",\"runAsNonRoot\",\"runAsUser\",\"seccompProfile\",\"capabilities\"],\"properties\":{\"allowPrivilegeEscalation\":{\"const\":false},\"readOnlyRootFilesystem\":{\"const\":true},\"runAsNonRoot\":{\"const\":true},\"runAsUser\":{\"type\":\"integer\",\"minimum\":10000,\"maximum\":2147483647},\"seccompProfile\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"type\"],\"properties\":{\"type\":{\"const\":\"RuntimeDefault\"}}},\"capabilities\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"drop\"],\"properties\":{\"drop\":{\"const\":[\"ALL\"]}}}}}}}}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"metadata\",\"immutable\",\"data\"],\"properties\":{\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"const\":\"ConfigMap\"},\"metadata\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"namespace\",\"labels\"],\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"labels\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"planeon.ai/run-nonce\",\"planeon.ai/tenant-id\"],\"properties\":{\"planeon.ai/run-nonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"planeon.ai/tenant-id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"}}}}},\"immutable\":{\"const\":true},\"data\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"fixture.json\"],\"properties\":{\"fixture.json\":{\"type\":\"string\",\"maxLength\":8192}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"metadata\",\"spec\"],\"properties\":{\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"const\":\"Service\"},\"metadata\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"namespace\",\"labels\"],\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"labels\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"planeon.ai/run-nonce\",\"planeon.ai/tenant-id\"],\"properties\":{\"planeon.ai/run-nonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"planeon.ai/tenant-id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"}}}}},\"spec\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"type\",\"selector\",\"ports\"],\"properties\":{\"type\":{\"const\":\"ClusterIP\"},\"selector\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"planeon.ai/run-nonce\",\"planeon.ai/tenant-id\"],\"properties\":{\"planeon.ai/run-nonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"},\"planeon.ai/tenant-id\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-z0-9](?:[a-z0-9.-]{0,62})$\"}}},\"ports\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":1,\"items\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"protocol\",\"port\",\"targetPort\"],\"properties\":{\"name\":{\"const\":\"probe\"},\"protocol\":{\"const\":\"TCP\"},\"port\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535},\"targetPort\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535}}}}}}}}]},\"resource\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"manifest\",\"manifestDigest\"],\"properties\":{\"manifest\":{\"$ref\":\"#/$defs/manifest\"},\"manifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"policy\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"admissionPolicyDigest\",\"resourceQuotaDigest\",\"limitRangeDigest\",\"namespaceUid\",\"resourceQuotaUid\",\"limitRangeUid\",\"serviceAccountUid\",\"rbacDigest\",\"networkPolicyDigest\",\"mutationBrokerDigest\",\"maxConcurrentOperations\",\"serviceAccountDigest\"],\"properties\":{\"admissionPolicyDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceQuotaDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"limitRangeDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"namespaceUid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-zA-Z0-9-]{1,128}$\"},\"resourceQuotaUid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-zA-Z0-9-]{1,128}$\"},\"limitRangeUid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-zA-Z0-9-]{1,128}$\"},\"serviceAccountUid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[a-zA-Z0-9-]{1,128}$\"},\"rbacDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"networkPolicyDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"mutationBrokerDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxConcurrentOperations\":{\"const\":1},\"serviceAccountDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}}}}")
_OBSERVATION_SPEC = json.loads("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"https://schemas.planeon.ai/internal/policy-observation/v1.json\",\"oneOf\":[{\"$ref\":\"#/$defs/binding\"},{\"$ref\":\"#/$defs/request\"},{\"$ref\":\"#/$defs/observation\"}],\"$defs\":{\"binding\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"profileDigest\",\"scope\",\"observer\",\"namespace\",\"projections\",\"enforcementPins\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.policy-observation-binding/v1\"},\"profileDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"scope\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"tenantId\",\"environmentId\",\"runNonce\",\"capacityNonce\",\"endpointId\",\"namespace\",\"serviceAccountSubject\",\"validFrom\",\"expiresAt\"],\"properties\":{\"tenantId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"environmentId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"capacityNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"serviceAccountSubject\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$\"},\"validFrom\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"},\"expiresAt\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"}}},\"observer\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"executableDigest\",\"manifestDigest\"],\"properties\":{\"executableDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"manifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"namespace\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"uid\"],\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"}}},\"projections\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"admissionPolicy\",\"resourceQuota\",\"limitRange\",\"serviceAccount\",\"rbac\",\"networkPolicy\",\"mutationBroker\"],\"properties\":{\"admissionPolicy\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"resourceQuota\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"limitRange\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"serviceAccount\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"rbac\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"networkPolicy\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"mutationBroker\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}}}},\"enforcementPins\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"admissionFenceDigest\",\"rbacClosureDigest\",\"networkEnforcementDigest\",\"hostPreflightDigest\"],\"properties\":{\"admissionFenceDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"rbacClosureDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"networkEnforcementDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"hostPreflightDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}}}},\"request\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"operation\",\"bindingDigest\",\"runNonce\",\"challenge\",\"sequence\",\"previousObservationDigest\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.policy-observation-request/v1\"},\"operation\":{\"const\":\"OBSERVE_POLICY\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"previousObservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"observation\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"runNonce\",\"challenge\",\"sequence\",\"previousObservationDigest\",\"observerBootId\",\"generation\",\"observedAt\",\"expiresAt\",\"namespace\",\"projections\",\"quota\",\"enforcement\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.policy-observation/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"previousObservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observerBootId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":36,\"pattern\":\"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"observedAt\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"},\"expiresAt\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"},\"namespace\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"name\",\"uid\",\"resourceVersion\"],\"properties\":{\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"projections\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"admissionPolicy\",\"resourceQuota\",\"limitRange\",\"serviceAccount\",\"rbac\",\"networkPolicy\",\"mutationBroker\"],\"properties\":{\"admissionPolicy\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"resourceQuota\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"limitRange\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"serviceAccount\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"rbac\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"networkPolicy\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}},\"mutationBroker\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"name\",\"namespace\",\"uid\",\"projectionDigest\",\"resourceVersion\"],\"properties\":{\"apiVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9./-]+$\"},\"kind\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z][A-Za-z0-9]+$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"namespace\":{\"oneOf\":[{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},{\"type\":\"null\"}]},\"uid\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"},\"projectionDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"resourceVersion\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9._:-]+$\"}}}}},\"quota\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"hard\",\"used\"],\"properties\":{\"hard\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"pods\",\"configMaps\",\"services\",\"cpuMillis\",\"memoryBytes\",\"ephemeralStorageBytes\"],\"properties\":{\"pods\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"configMaps\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"services\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"cpuMillis\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"memoryBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"ephemeralStorageBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991}}},\"used\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"pods\",\"configMaps\",\"services\",\"cpuMillis\",\"memoryBytes\",\"ephemeralStorageBytes\"],\"properties\":{\"pods\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"configMaps\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"services\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"cpuMillis\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"memoryBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"ephemeralStorageBytes\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991}}}}},\"enforcement\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"policyGeneration\",\"admissionFenceDigest\",\"rbacClosureDigest\",\"networkEnforcementDigest\",\"hostPreflightDigest\"],\"properties\":{\"policyGeneration\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"admissionFenceDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"rbacClosureDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"networkEnforcementDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"hostPreflightDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}}}}}}")


def require(ok, reason):
    if not ok:
        raise ConformanceError(reason, "fixed proxy refused; no execution authority")


def _bounded(value, maximum, depth=0, budget=None):
    if budget is None:
        budget = [maximum]
    kind = type(value)
    require(depth <= 16 and kind in (dict, list, str, int, bool, type(None)), "PROXY_DATA_TYPE")
    budget[0] -= len(value) + 1 if kind in (str, dict, list) else 1
    require(budget[0] >= 0, "PROXY_DATA_SIZE")
    if kind is int:
        require(abs(value) <= 9007199254740991, "PROXY_INTEGER_RANGE")
    if kind is dict:
        for key, child in value.items():
            require(type(key) is str, "PROXY_DATA_KEY")
            _bounded(key, maximum, depth + 1, budget)
            _bounded(child, maximum, depth + 1, budget)
    elif kind is list:
        for child in value:
            _bounded(child, maximum, depth + 1, budget)


def document(value, maximum=262144):
    if type(value) is bytes:
        require(0 < len(value) <= maximum, "PROXY_DATA_SIZE")
        raw, value = value, require_canonical_document(value)
        require(canonical_bytes(value) == raw, "PROXY_NONCANONICAL_BYTES")
    _bounded(value, maximum)
    raw = canonical_bytes(value)
    require(len(raw) <= maximum, "PROXY_DATA_SIZE")
    return require_canonical_document(raw)


def _shape(value, spec, definitions):
    # Implements only keywords in the pinned private specification. No external
    # references, selectable schema, extension keyword or executable validator.
    allowed = {"$schema", "$id", "$defs", "$ref", "oneOf", "type", "additionalProperties",
               "required", "properties", "const", "enum", "items", "minItems", "maxItems",
               "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum"}
    require(type(spec) is dict and not set(spec) - allowed, "PROXY_SPEC_INVALID")
    if "$ref" in spec:
        name = spec["$ref"]
        require(type(name) is str and name.startswith("#/$defs/") and name[8:] in definitions, "PROXY_SPEC_INVALID")
        _shape(value, definitions[name[8:]], definitions)
    if "oneOf" in spec:
        count = 0
        for option in spec["oneOf"]:
            try:
                _shape(value, option, definitions)
                count += 1
            except ConformanceError:
                pass
        require(count == 1, "PROXY_SHAPE_INVALID")
    if "type" in spec:
        expected = {"object": dict, "array": list, "string": str, "integer": int,
                    "boolean": bool, "null": type(None)}[spec["type"]]
        require(type(value) is expected, "PROXY_SHAPE_INVALID")
    if "const" in spec:
        require(canonical_bytes(value) == canonical_bytes(spec["const"]), "PROXY_CONSTANT_INVALID")
    if "enum" in spec:
        require(any(canonical_bytes(value) == canonical_bytes(v) for v in spec["enum"]), "PROXY_ENUM_INVALID")
    if type(value) is dict and "properties" in spec:
        require(set(spec.get("required", ())) <= set(value), "PROXY_FIELD_MISSING")
        require(spec.get("additionalProperties") is False and not set(value) - set(spec["properties"]),
                "PROXY_FIELD_UNKNOWN")
        for key, item in value.items():
            _shape(item, spec["properties"][key], definitions)
    if type(value) is list:
        require(spec.get("minItems", 0) <= len(value) <= spec.get("maxItems", 4096), "PROXY_COLLECTION_SIZE")
        if spec.get("uniqueItems"):
            require(len({canonical_bytes(v) for v in value}) == len(value), "PROXY_DUPLICATE")
        for item in value:
            if "items" in spec:
                _shape(item, spec["items"], definitions)
    if type(value) is str:
        require(spec.get("minLength", 0) <= len(value) <= spec.get("maxLength", 262144), "PROXY_STRING_SIZE")
        if "pattern" in spec:
            require(re.fullmatch(spec["pattern"], value, re.ASCII) is not None, "PROXY_STRING_INVALID")
    if type(value) is int:
        require(spec.get("minimum", -9007199254740991) <= value <= spec.get("maximum", 9007199254740991),
                "PROXY_INTEGER_RANGE")


def _time(value):
    require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
            "PROXY_TIME_INVALID")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_profile(value):
    """Detached validated data; not a credential, policy observation or lease."""
    profile = document(value)
    _shape(profile, _PROFILE_SPEC, _PROFILE_SPEC["$defs"])
    binding, entries, policy = profile["binding"], profile["capacityEntries"], profile["policy"]
    start, end = _time(binding["validFrom"]), _time(binding["expiresAt"])
    require(0 < (end - start).total_seconds() <= 900, "profile validity exceeded")
    subject = binding["serviceAccountSubject"]
    require(subject.startswith("system:serviceaccount:" + binding["namespace"] + ":"), "subject namespace mismatch")
    credentials = entries["credentialIdentities"]
    expected_credentials = [(binding["endpointId"], "CAMPAIGN_PROXY_CLIENT_MTLS")]
    if profile["resources"]:
        require(binding["apiEndpointId"] is not None and binding["apiEndpointId"] != binding["endpointId"],
                 "separate API endpoint required")
        expected_credentials.append((binding["apiEndpointId"], "KUBERNETES_PROXY_SERVER_MTLS"))
    else:
        require(binding["apiEndpointId"] is None, "unused API endpoint forbidden")
    require([(c["endpointId"], c["purpose"]) for c in credentials] == expected_credentials, "credential inventory mismatch")
    for item in credentials:
        require(item["subject"] == subject and item["expiresAt"] == binding["expiresAt"], "credential binding mismatch")
    for field in ("certificateDigest", "clientSpkiDigest"):
        require(len({c[field] for c in credentials}) == len(credentials), "client/server credential reuse")
    rule = entries["campaignProxyRules"][0]
    require(rule["endpointId"] == binding["endpointId"] and rule["namespace"] == binding["namespace"]
             and rule["paths"] == PATHS, "fixed proxy rule mismatch")
    reference_ids = set()
    references = entries["preexistingResourceRefs"]
    for item in references:
        key = (item["apiVersion"], item["kind"], item["namespace"], item["name"])
        require(item["namespace"] == binding["namespace"] and key not in reference_ids, "duplicate or foreign reference")
        reference_ids.add(key)
    for kind, uid_key, digest_key in (("ResourceQuota", "resourceQuotaUid", "resourceQuotaDigest"),
            ("LimitRange", "limitRangeUid", "limitRangeDigest"), ("ServiceAccount", "serviceAccountUid", "serviceAccountDigest")):
        matches = [r for r in references if r["kind"] == kind]
        require(len(matches) == 1 and matches[0]["uid"] == policy[uid_key]
                 and matches[0]["observedDigest"] == policy[digest_key], "required policy reference mismatch")
        if kind == "ServiceAccount":
            require(matches[0]["name"] == subject.rsplit(":", 1)[1], "service account name mismatch")
    require(len({r["uid"] for r in references}) == len(references), "duplicate resource UID")
    expected_labels = {"planeon.ai/run-nonce": binding["runNonce"], "planeon.ai/tenant-id": binding["tenantId"]}
    names, units, required_gvk, required_api = set(), dict.fromkeys(profile["quota"], 0), {}, set()
    kinds = {"Pod": ("pods", "pods"), "ConfigMap": ("configmaps", "configMaps"), "Service": ("services", "services")}
    images = set()
    for row in profile["resources"]:
        manifest = row["manifest"]
        raw = canonical_bytes(manifest)
        require(len(raw) <= 16384 and row["manifestDigest"] == byte_digest(raw), "manifest digest or size mismatch")
        meta, kind = manifest["metadata"], manifest["kind"]
        key = (kind, meta["name"])
        require(key not in names and meta["namespace"] == binding["namespace"]
                 and meta["labels"] == expected_labels, "resource scope or logical identity mismatch")
        require(("v1", kind, meta["namespace"], meta["name"]) not in reference_ids, "existing resource takeover")
        names.add(key)
        required_gvk.setdefault(kind, set()).add(meta["name"])
        api_resource, unit = kinds[kind]
        units[unit] += 1
        required_api.update((binding["apiEndpointId"], verb, api_resource, meta["name"]) for verb in ("create", "get", "delete"))
        if kind == "Pod":
            spec = manifest["spec"]
            require(spec["serviceAccountName"] == subject.rsplit(":", 1)[1], "pod service account mismatch")
            container = spec["containers"][0]
            quantities = container["resources"]
            require(quantities["requests"] == quantities["limits"], "unequal requests and limits")
            units["cpuMillis"] += int(quantities["limits"]["cpu"][:-1])
            units["memoryBytes"] += int(quantities["limits"]["memory"])
            units["ephemeralStorageBytes"] += int(quantities["limits"]["ephemeral-storage"])
            images.add(container["image"])
        elif kind == "Service":
            require(manifest["spec"]["selector"] == expected_labels, "foreign selector")
    observed_gvk = {}
    for rule in entries["permittedGvksAndVerbs"]:
        require(rule["kind"] not in observed_gvk, "duplicate GVK rule")
        observed_gvk[rule["kind"]] = set(rule["names"])
    require(observed_gvk == required_gvk, "exact GVK/name grants required")
    api = set()
    for rule in entries["kubernetesApiRules"]:
        key = (rule["endpointId"], rule["verb"], rule["resource"], rule["name"])
        require(rule["namespace"] == binding["namespace"] and key not in api, "API scope or duplicate rule")
        api.add(key)
    require(api == required_api, "exact server API rules required")
    require(images == set(profile["localImages"]), "image substitution or unused image")
    require(all(units[k] <= profile["quota"][k] for k in units), "quota exceeded")

    return profile


def _observation_shape(value, variant, maximum):
    value = document(value, maximum)
    def ascii_fields(item):
        if type(item) is str:
            require(all(32 <= ord(c) <= 126 for c in item), "OBSERVATION_ASCII_REQUIRED")
        elif type(item) is dict:
            for key, child in item.items():
                ascii_fields(key)
                ascii_fields(child)
        elif type(item) is list:
            for child in item:
                ascii_fields(child)
    ascii_fields(value)
    _shape(value, _OBSERVATION_SPEC["$defs"][variant], _OBSERVATION_SPEC["$defs"])
    return value


def validate_messages(binding, request, observation, profile, now, previous=None):
    """DATA_CHECK_ONLY: authenticated peer and real controls remain mandatory."""
    binding = _observation_shape(binding, "binding", 65536)
    request = _observation_shape(request, "request", 16384)
    observation = _observation_shape(observation, "observation", 65536)
    profile = validate_profile(profile)
    require(binding["profileDigest"] == canonical_digest(profile), "profile digest")
    scope = {k: v for k, v in profile["binding"].items() if k != "apiEndpointId"}
    require(binding["scope"] == scope, "independent profile scope")
    require(binding["namespace"] == {"name": scope["namespace"], "uid": profile["policy"]["namespaceUid"]},
             "namespace binding")
    refs = profile["capacityEntries"]["preexistingResourceRefs"]
    for key in POLICIES:
        expected = binding["projections"][key]
        require(expected["projectionDigest"] == profile["policy"][key + "Digest"], "policy digest")
        require(expected["namespace"] in (None, scope["namespace"]), "foreign policy")
        if key in ("resourceQuota", "limitRange", "serviceAccount"):
            kind = {"resourceQuota": "ResourceQuota", "limitRange": "LimitRange", "serviceAccount": "ServiceAccount"}[key]
            matches = [r for r in refs if r["kind"] == kind]
            require(len(matches) == 1, "required reference")
            ref = matches[0]
            require(expected == {**{k: ref[k] for k in ("apiVersion", "kind", "namespace", "name", "uid")},
                                  "projectionDigest": ref["observedDigest"]}, "policy identity")
        actual = {k: v for k, v in observation["projections"][key].items() if k != "resourceVersion"}
        require(actual == expected, "observed identity or digest")
    require({k: observation["namespace"][k] for k in ("name", "uid")} == binding["namespace"], "observed namespace")
    require(request["bindingDigest"] == canonical_digest(binding)
             and request["runNonce"] == scope["runNonce"], "request binding")
    for field in ("bindingDigest", "runNonce", "challenge", "sequence", "previousObservationDigest"):
        require(observation[field] == request[field], "response substitution")
    if previous is None:
        require(request["sequence"] == 1 and request["previousObservationDigest"] == ZERO, "initial chain")
    else:
        _observation_shape(previous, "observation", 65536)
        require(previous["bindingDigest"] == request["bindingDigest"]
                 and previous["runNonce"] == request["runNonce"]
                 and request["sequence"] == previous["sequence"] + 1
                 and request["previousObservationDigest"] == canonical_digest(previous), "chain gap")
        require(observation["observerBootId"] == previous["observerBootId"]
                 and observation["generation"] == previous["generation"]
                 and request["challenge"] != previous["challenge"], "restart, drift or reused challenge")
        require(_time(observation["observedAt"]) >= _time(previous["observedAt"]), "clock rollback")
    start, end, instant = _time(observation["observedAt"]), _time(observation["expiresAt"]), _time(now)
    require(_time(scope["validFrom"]) <= start <= instant < end <= _time(scope["expiresAt"]), "stale or future")
    require(0 < (end - start).total_seconds() <= 5, "freshness window")
    require(observation["enforcement"] == {"policyGeneration": observation["generation"],
                                           **binding["enforcementPins"]}, "enforcement proof mismatch")
    for unit, requested in profile["quota"].items():
        hard, used = observation["quota"]["hard"][unit], observation["quota"]["used"][unit]
        require(type(requested) is int and 0 <= requested <= 9007199254740991
                 and used <= hard and requested <= hard - used, "actual quota headroom")

    return observation


def retained_profile(envelope, capacity, plan, release, kit):
    """Use retained verified bytes only; no file lookup or selected backend."""
    require(type(kit) in (dict, MappingProxyType), "PROFILE_CUSTODY_REQUIRED")
    def member(path, maximum):
        rows = [r for r in release["tree"] if r["path"] == path]
        raw = kit.get(path)
        require(len(rows) == 1 and type(raw) is bytes and 0 < len(raw) <= maximum, "PROFILE_MEMBER_MISSING")
        row = rows[0]
        require(row == {"path": path, "mode": "0444", "size": len(raw), "sha256": byte_digest(raw)},
                "PROFILE_MEMBER_CHANGED")
        return raw
    profile = validate_profile(member(PROFILE_PATH, 262144))
    scope, policy = profile["binding"], profile["policy"]
    expected = {"tenantId": envelope["tenantId"], "environmentId": envelope["environmentId"],
                "runNonce": envelope["nonce"], "capacityNonce": capacity["nonce"],
                "endpointId": plan["endpointId"], "namespace": plan["namespace"],
                "serviceAccountSubject": capacity["serviceAccountSubject"]}
    require(all(scope[k] == v for k, v in expected.items()), "PROFILE_SCOPE_MISMATCH")
    require(all(capacity[k] == v for k, v in profile["capacityEntries"].items()), "PROFILE_CAPACITY_MISMATCH")
    for field in ("admissionPolicyDigest", "resourceQuotaDigest"):
        require(policy[field] == capacity[field] == envelope[field], "PROFILE_POLICY_MISMATCH")
    require(policy["limitRangeDigest"] == capacity["limitRangeDigest"], "PROFILE_POLICY_MISMATCH")
    require(max(require_time(envelope["issuedAt"], "start"), require_time(capacity["validFrom"], "start"))
            <= _time(scope["validFrom"]) < _time(scope["expiresAt"])
            <= min(require_time(envelope["expiresAt"], "end"), require_time(capacity["expiresAt"], "end")),
            "PROFILE_WINDOW_MISMATCH")
    endpoints = {e["endpointId"]: e for e in envelope["endpoints"]}
    require(len(endpoints) == len(envelope["endpoints"]), "PROFILE_ENDPOINT_DUPLICATE")
    endpoint = endpoints.get(scope["endpointId"])
    require(endpoint is not None and endpoint["kind"] == "CAMPAIGN_PROXY"
            and profile["capacityEntries"]["campaignProxyRules"][0]["port"] == endpoint["port"],
            "PROFILE_ENDPOINT_MISMATCH")
    if profile["resources"]:
        require(scope["apiEndpointId"] in endpoints and endpoints[scope["apiEndpointId"]]["kind"] == "KUBERNETES_API_PROXY",
                "PROFILE_API_ENDPOINT_MISSING")
    image_digests = set(plan["images"].values())
    require(all(image.rsplit("@", 1)[1] in image_digests for image in profile["localImages"]), "PROFILE_IMAGE_NOT_RELEASED")
    observation_binding = _observation_shape(member(OBSERVATION_PATH, 65536), "binding", 65536)
    require(observation_binding["profileDigest"] == canonical_digest(profile)
            and observation_binding["scope"] == {k: v for k, v in scope.items() if k != "apiEndpointId"}
            and observation_binding["namespace"] == {"name": scope["namespace"], "uid": policy["namespaceUid"]},
            "PROFILE_OBSERVATION_MISMATCH")
    for key in POLICIES:
        raw = member("campaigns/platform/linux-baseline/proxy-policy/" + key + ".json", 65536)
        projection = document(raw, 65536)
        closed(projection, ("apiVersion", "kind", "metadata", "spec"))
        closed(projection["metadata"], ("name", "namespace", "uid"))
        expected_projection = {k: projection[k] for k in ("apiVersion", "kind")}
        expected_projection.update(projection["metadata"], projectionDigest=byte_digest(raw))
        require(byte_digest(raw) == policy[key + "Digest"]
                and observation_binding["projections"][key] == expected_projection, "PROFILE_PROJECTION_MISMATCH")
    ca_path = endpoint["tls"]["caCertificateFileReference"]
    prefix = envelope["conformanceKitRoot"] + "/"
    require(ca_path.startswith(prefix) and ca_path[len(prefix):] and ".." not in ca_path[len(prefix):].split("/"),
            "PROFILE_CA_NOT_RELEASED")
    ca = member(ca_path[len(prefix):], 262144)
    require(ca.startswith(b"-----BEGIN CERTIFICATE-----"), "PROFILE_CA_INVALID")
    return profile, observation_binding, endpoint, ca


def resource_units(profile):
    units = dict.fromkeys(UNITS, 0)
    for row in profile["resources"]:
        manifest = row["manifest"]
        units[{"Pod": "pods", "ConfigMap": "configMaps", "Service": "services"}[manifest["kind"]]] += 1
        if manifest["kind"] == "Pod":
            limits = manifest["spec"]["containers"][0]["resources"]["limits"]
            for field, value in (("cpuMillis", int(limits["cpu"][:-1])),
                                 ("memoryBytes", int(limits["memory"])),
                                 ("ephemeralStorageBytes", int(limits["ephemeral-storage"]))):
                units[field] += value
    require(all(type(v) is int and 0 <= v <= 9007199254740991 for v in units.values()), "ADMISSION_QUOTA_OVERFLOW")
    return units


def validate_observed_manifest(observed, expected, uid=None):
    """Reject post-defaulting substitutions; no field becomes endpoint authority."""
    import ipaddress
    actual, signed = document(observed, 16384), document(expected, 16384)
    meta = actual.get("metadata", {})
    assigned_uid, version = meta.get("uid"), meta.get("resourceVersion")
    require(type(assigned_uid) is str and re.fullmatch("[A-Za-z0-9-]{1,128}", assigned_uid)
            and type(version) is str and re.fullmatch("[A-Za-z0-9._:-]{1,128}", version), "ADMISSION_IDENTITY_MISSING")
    require(uid is None or assigned_uid == uid, "ADMISSION_UID_CHANGED")
    for field in ("uid", "resourceVersion", "creationTimestamp"):
        meta.pop(field, None)
    if actual.get("kind") == "Service":
        address = actual.get("spec", {}).pop("clusterIP", None)
        require(type(address) is str and str(ipaddress.ip_address(address)) == address, "ADMISSION_SERVICE_ADDRESS")
    require(actual == signed, "ADMISSION_POST_MUTATION_MISMATCH")
    return assigned_uid, version


def cleanup_receipt(binding_digest, operation, now, remaining, previous=ZERO):
    require_digest(binding_digest, "bindingDigest")
    require_digest(previous, "previousReceiptDigest")
    require(operation in CASES and type(remaining) is list and len(remaining) <= 32, "CLEANUP_SCOPE")
    require_time(now, "observedAt")
    identities = set()
    reasons = ("DELETE_DENIED", "UID_CHANGED", "DEADLINE", "IO_AMBIGUOUS", "OBSERVATION_UNAVAILABLE")
    for row in remaining:
        closed(row, ("apiVersion", "kind", "namespace", "name", "uid", "manifestDigest", "reasonCode"))
        require(row["apiVersion"] == "v1" and row["kind"] in ("Pod", "ConfigMap", "Service")
                and row["reasonCode"] in reasons, "CLEANUP_SCOPE")
        for field in ("namespace", "name"):
            require(type(row[field]) is str and re.fullmatch("[a-z0-9][a-z0-9.-]{0,62}", row[field]), "CLEANUP_SCOPE")
        require(row["uid"] is None and row["reasonCode"] == "IO_AMBIGUOUS"
                or type(row["uid"]) is str and re.fullmatch("[A-Za-z0-9-]{1,128}", row["uid"]), "CLEANUP_UID")
        require_digest(row["manifestDigest"], "manifestDigest")
        key = (row["kind"], row["namespace"], row["name"])
        require(key not in identities, "CLEANUP_DUPLICATE")
        identities.add(key)
    return document({"schemaVersion": "planeon.internal.proxy-cleanup/v1",
        "bindingDigest": binding_digest, "operation": operation, "observedAt": now,
        "state": "CLEANUP_PENDING" if remaining else "CLEAN", "remainingResources": remaining,
        "previousReceiptDigest": previous}, 16384)


LEDGER_FIELDS = ("sequence", "previousDigest", "binding", "state", "operation", "observedAt", "cleanup")
BINDING_FIELDS = ("tenantId", "environmentId", "runNonce", "capacityNonce", "endpointId",
                  "releaseDigest", "packetDigest", "commandSetDigest", "profileDigest")


def admission_binding(envelope, capacity, profile):
    return {"tenantId": envelope["tenantId"], "environmentId": envelope["environmentId"],
        "runNonce": envelope["nonce"], "capacityNonce": capacity["nonce"],
        "endpointId": profile["binding"]["endpointId"], "releaseDigest": envelope["campaignReleaseDigest"],
        "packetDigest": envelope["packetDigest"], "commandSetDigest": envelope["commandSetDigest"],
        "profileDigest": canonical_digest(profile)}


def parse_reservations(raw):
    require(type(raw) is bytes and len(raw) <= 4194304 and (not raw or raw.endswith(b"\n")), "ADMISSION_HISTORY_INVALID")
    lines = raw.splitlines()
    require(len(lines) <= 4096, "ADMISSION_HISTORY_FULL")
    previous, reservations = ZERO, {}
    for index, line in enumerate(lines, 1):
        row = document(line, 32768)
        closed(row, LEDGER_FIELDS)
        binding = row["binding"]
        closed(binding, BINDING_FIELDS)
        for field in BINDING_FIELDS:
            if field.endswith("Digest"):
                require_digest(binding[field], field)
            else:
                require(type(binding[field]) is str and re.fullmatch("[a-z0-9][a-z0-9.-]{0,62}", binding[field]),
                        "ADMISSION_BINDING_INVALID")
        require(type(row["sequence"]) is int and row["sequence"] == index and row["previousDigest"] == previous,
                "ADMISSION_HISTORY_CHAIN")
        instant = require_time(row["observedAt"], "observedAt")
        key = (binding["tenantId"], binding["runNonce"])
        prior = reservations.get(key)
        if prior is None:
            require(row["state"] == "RESERVED" and row["operation"] is None and row["cleanup"] is None,
                    "ADMISSION_HISTORY_INITIAL")
            # Unknown crash/cleanup history holds all capacity; no automatic
            # restart reconciliation or release through expired timestamps.
            require(not any(v["held"] for v in reservations.values()), "ADMISSION_CAPACITY_HELD")
            prior = dict(binding=binding, done=[], current=None, held=True, cleanupDigest=ZERO, last=instant)
            reservations[key] = prior
        else:
            require(binding == prior["binding"] and instant >= prior["last"] and prior["held"],
                    "ADMISSION_HISTORY_TRANSITION")
            operation = row["operation"]
            require(type(operation) is str and operation in CASES, "ADMISSION_OPERATION_INVALID")
            if row["state"] == "RUNNING":
                require(prior["current"] is None and operation not in prior["done"] and row["cleanup"] is None,
                        "ADMISSION_OPERATION_REPLAY")
                prior["current"] = operation
                prior["done"].append(operation)
            elif row["state"] == "RECORDED":
                require(prior["current"] == operation and type(row["cleanup"]) is dict, "ADMISSION_HISTORY_TRANSITION")
                receipt = row["cleanup"]
                expected = cleanup_receipt(canonical_digest(binding), operation, row["observedAt"],
                                           receipt.get("remainingResources"), prior["cleanupDigest"])
                require(receipt == expected, "ADMISSION_CLEANUP_INVALID")
                prior["cleanupDigest"] = canonical_digest(receipt)
                prior["current"] = None if receipt["state"] == "CLEAN" else operation
                # The process remains one-run exclusive. All ten operations and
                # independently confirmed CLEAN are needed to release capacity.
                prior["held"] = len(prior["done"]) < len(CASES) or receipt["state"] != "CLEAN"
            else:
                require(False, "ADMISSION_HISTORY_TRANSITION")
        prior["last"] = instant
        previous = canonical_digest(row)
    return reservations, previous, len(lines)


class _AdmissionLog:
    """Shared durable algorithm. Instances/data alone authorize no effect."""
    def __init__(self, storage):
        self.storage, self.poisoned = storage, False

    def record(self, binding, state, operation, now, cleanup=None):
        require(not self.poisoned, "ADMISSION_STORAGE_AMBIGUOUS")
        with self.storage.transaction() as io:
            before = io.read()
            _, previous, count = parse_reservations(before)
            row = {"sequence": count + 1, "previousDigest": previous, "binding": binding,
                   "state": state, "operation": operation, "observedAt": now, "cleanup": cleanup}
            after = before + canonical_bytes(row) + b"\n"
            parse_reservations(after)
            try:
                io.append(after[len(before):])
                io.sync()
                require(io.read() == after, "ADMISSION_READBACK_FAILED")
            except BaseException:
                self.poisoned = True
                raise
            return canonical_digest(row)

# Fixed, source-owned MET-REPAIR-014 message schema. This is validation data;
# neither a valid message nor this parser can construct an installed execution.
_BROKER_SPEC = json.loads("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"oneOf\":[{\"$ref\":\"#/$defs/binding\"},{\"$ref\":\"#/$defs/dispatch\"},{\"$ref\":\"#/$defs/frame\"},{\"$ref\":\"#/$defs/workerStart\"}],\"$defs\":{\"binding\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"profileDigest\",\"observationBindingDigest\",\"brokerManifestDigest\",\"brokerExecutableDigest\",\"workerManifestDigest\",\"workerArtifactDigest\",\"caseResourceDigests\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-binding/v1\"},\"profileDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationBindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"brokerManifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"brokerExecutableDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"workerManifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"workerArtifactDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"caseResourceDigests\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"],\"properties\":{\"HOST_ISOLATION_NEGATIVES\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"LINUX_TARGET_BUILD\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"FULL_PREDECESSOR_REGRESSION\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"CONTROL_CONTAINER_STARTUP\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"POSTGRES_MIGRATION_AND_RLS\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"DURABLE_RESTART\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"ARBITRARY_NON_ROOT_UID\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"READ_ONLY_ROOT_FILESYSTEM\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"KUBERNETES_SMOKE\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true},\"DEFAULT_DENY_NETWORK\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true}}}}},\"dispatch\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"operation\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-dispatch/v1\"},\"operation\":{\"const\":\"EXECUTE_FIXED_PROBE\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"}}},\"frame\":{\"oneOf\":[{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"STARTED\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"workerPid\",\"workerStartTicks\"],\"properties\":{\"workerPid\":{\"type\":\"integer\",\"minimum\":2,\"maximum\":2147483647},\"workerStartTicks\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"RESOURCE_ACTION\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"actionId\",\"verb\",\"manifestDigest\"],\"properties\":{\"actionId\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":256},\"verb\":{\"enum\":[\"CREATE\",\"GET\",\"DELETE\"]},\"manifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"RESOURCE_RESULT\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"actionId\",\"outcome\",\"objectBase64\"],\"properties\":{\"actionId\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":256},\"outcome\":{\"enum\":[\"ABSENT\",\"CREATED\",\"PRESENT\",\"DELETED\",\"DENIED\",\"AMBIGUOUS\"]},\"objectBase64\":{\"oneOf\":[{\"type\":\"null\"},{\"type\":\"string\",\"minLength\":4,\"maxLength\":21848,\"pattern\":\"^[A-Za-z0-9+/]+={0,2}$\"}]}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"RECEIPT_CHUNK\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"index\",\"dataBase64\"],\"properties\":{\"index\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":170},\"dataBase64\":{\"type\":\"string\",\"minLength\":4,\"maxLength\":32768,\"pattern\":\"^[A-Za-z0-9+/]+={0,2}$\"}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"CLEANUP_RECORDED\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"cleanupDigest\",\"state\",\"remainingResources\"],\"properties\":{\"cleanupDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"state\":{\"enum\":[\"CLEAN\",\"CLEANUP_PENDING\"]},\"remainingResources\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"apiVersion\",\"kind\",\"namespace\",\"name\",\"uid\",\"manifestDigest\",\"reasonCode\"],\"properties\":{\"apiVersion\":{\"const\":\"v1\"},\"kind\":{\"enum\":[\"Pod\",\"ConfigMap\",\"Service\"]},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"name\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"uid\":{\"oneOf\":[{\"type\":\"null\"},{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[A-Za-z0-9-]{1,128}$\"}]},\"manifestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reasonCode\":{\"enum\":[\"DELETE_DENIED\",\"UID_CHANGED\",\"DEADLINE\",\"IO_AMBIGUOUS\",\"OBSERVATION_UNAVAILABLE\"]}}},\"maxItems\":32,\"minItems\":0,\"uniqueItems\":true}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"TERMINAL\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"status\",\"receiptSize\",\"receiptDigest\",\"cleanupDigest\",\"workerReaped\"],\"properties\":{\"status\":{\"enum\":[\"COMPLETED\",\"FAILED\",\"UNAVAILABLE\"]},\"receiptSize\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4194304},\"receiptDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"cleanupDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"workerReaped\":{\"const\":true}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"ABORT\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"reason\"],\"properties\":{\"reason\":{\"enum\":[\"DEADLINE\",\"REVOKED\",\"POLICY_LOST\",\"PEER_CHANGED\",\"IO_AMBIGUOUS\",\"INVALID_FRAME\"]}}}}},{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"bindingDigest\",\"reservationDigest\",\"runNonce\",\"caseId\",\"requestDigest\",\"observationDigest\",\"generation\",\"challenge\",\"executionId\",\"sequence\",\"previousDigest\",\"kind\",\"payload\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-frame/v1\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"reservationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":63,\"pattern\":\"^[a-z0-9][a-z0-9.-]{0,62}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observationDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"challenge\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"sequence\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2048},\"previousDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"kind\":{\"const\":\"REFUSED\"},\"payload\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"reason\"],\"properties\":{\"reason\":{\"enum\":[\"UNAVAILABLE\",\"REPLAY\",\"GENERATION_MISMATCH\",\"CAPACITY_HELD\",\"INVALID_AUTHORITY\"]}}}}}]},\"workerStart\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"operation\",\"executionId\",\"bindingDigest\",\"caseId\",\"requestDigest\",\"generation\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.broker-worker/v1\"},\"operation\":{\"const\":\"START\"},\"executionId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"},\"bindingDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"caseId\":{\"enum\":[\"HOST_ISOLATION_NEGATIVES\",\"LINUX_TARGET_BUILD\",\"FULL_PREDECESSOR_REGRESSION\",\"CONTROL_CONTAINER_STARTUP\",\"POSTGRES_MIGRATION_AND_RLS\",\"DURABLE_RESTART\",\"ARBITRARY_NON_ROOT_UID\",\"READ_ONLY_ROOT_FILESYSTEM\",\"KUBERNETES_SMOKE\",\"DEFAULT_DENY_NETWORK\"]},\"requestDigest\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":71,\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"generation\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":64,\"pattern\":\"^[0-9a-f]{64}$\"}}}}}")
BROKER_BINDING_PATH = "campaigns/platform/linux-baseline/broker-execution-binding.json"
BROKER_COMMON = ("bindingDigest", "reservationDigest", "runNonce", "caseId",
                 "requestDigest", "observationDigest", "generation", "challenge")


def broker_document(value, variant):
    require(variant in ("binding", "dispatch", "frame", "workerStart"), "BROKER_VARIANT_INVALID")
    result = document(value, 16384 if variant in ("dispatch", "workerStart") else 65536)
    _shape(result, _BROKER_SPEC["$defs"][variant], _BROKER_SPEC["$defs"])
    return result


def retained_broker_binding(profile, observation_binding, release, kit):
    raw = kit.get(BROKER_BINDING_PATH)
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "BROKER_BINDING_MISSING")
    rows = [r for r in release["tree"] if r["path"] == BROKER_BINDING_PATH]
    require(rows == [{"path": BROKER_BINDING_PATH, "mode": "0444",
                     "size": len(raw), "sha256": byte_digest(raw)}], "BROKER_BINDING_CUSTODY")
    binding = broker_document(raw, "binding")
    require(binding["profileDigest"] == canonical_digest(profile)
            and binding["observationBindingDigest"] == canonical_digest(observation_binding),
            "BROKER_INPUT_SUBSTITUTION")
    assigned = [digest for case in CASES for digest in binding["caseResourceDigests"][case]]
    require(len(assigned) == len(set(assigned))
            and set(assigned) == {r["manifestDigest"] for r in profile["resources"]},
            "BROKER_RESOURCE_OWNERSHIP")
    return binding


def _base64_bytes(value, maximum):
    import base64
    require(type(value) is str, "BROKER_BASE64_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ConformanceError("BROKER_BASE64_INVALID", "invalid bounded broker data") from exc
    require(0 < len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value,
            "BROKER_BASE64_INVALID")
    return raw


class BrokerTranscript:
    """Incremental DATA parser shared with the fixed transport, never a grant.

    Direction, frame chain, action ownership and terminal receipt must agree.
    A parse failure poisons the instance. Callers must separately verify installed
    custody and enforcement before I/O or effects, including for zero resources.
    """
    def __init__(self, binding, dispatch):
        self.binding = broker_document(binding, "binding")
        self.dispatch = broker_document(dispatch, "dispatch")
        require(self.dispatch["bindingDigest"] == canonical_digest(self.binding), "BROKER_BINDING_MISMATCH")
        self.sequence, self.previous, self.execution = 0, ZERO, None
        self.pending, self.cleanup, self.terminal = None, None, None
        self.actions, self.chunks = set(), []
        self.receipt_size, self.failed_action, self.poisoned = 0, False, False

    def accept(self, raw, sender):
        require(not self.poisoned and self.terminal is None, "BROKER_TRANSCRIPT_CLOSED")
        try:
            frame = broker_document(raw, "frame")
            require(sender in ("BROKER", "SERVER"), "BROKER_DIRECTION_INVALID")
            kind, payload = frame["kind"], frame["payload"]
            require((sender == "SERVER") == (kind in ("RESOURCE_RESULT", "CLEANUP_RECORDED", "ABORT")),
                    "BROKER_DIRECTION_INVALID")
            require(all(frame[k] == self.dispatch[k] for k in BROKER_COMMON)
                    and frame["sequence"] == self.sequence + 1
                    and frame["previousDigest"] == self.previous, "BROKER_TRANSCRIPT_BINDING")
            if self.execution is None:
                require(kind == "STARTED", "BROKER_CONTROLLED_START_REQUIRED")
                self.execution = frame["executionId"]
            else:
                require(frame["executionId"] == self.execution and kind != "STARTED",
                        "BROKER_EXECUTION_REPLAY")
            if kind == "RESOURCE_ACTION":
                require(self.pending is None and not self.chunks and self.cleanup is None
                        and payload["actionId"] not in self.actions
                        and payload["manifestDigest"] in self.binding["caseResourceDigests"][self.dispatch["caseId"]],
                        "BROKER_RESOURCE_ACTION_INVALID")
                self.pending = document(payload, 16384)
                self.actions.add(payload["actionId"])
            elif kind == "RESOURCE_RESULT":
                require(self.pending is not None and payload["actionId"] == self.pending["actionId"],
                        "BROKER_RESULT_WITHOUT_ACTION")
                permitted = {"CREATE": {"CREATED"}, "GET": {"PRESENT", "ABSENT"}, "DELETE": {"DELETED"}}
                require(payload["outcome"] in permitted[self.pending["verb"]] | {"DENIED", "AMBIGUOUS"},
                        "BROKER_RESOURCE_OUTCOME_INVALID")
                has_object = payload["outcome"] in ("CREATED", "PRESENT")
                require(has_object == (payload["objectBase64"] is not None), "BROKER_RESOURCE_OBJECT_INVALID")
                if has_object:
                    value = document(_base64_bytes(payload["objectBase64"], 16384), 16384)
                    require(type(value) is dict, "BROKER_RESOURCE_OBJECT_INVALID")
                self.failed_action |= payload["outcome"] in ("DENIED", "AMBIGUOUS")
                self.pending = None
            elif kind == "RECEIPT_CHUNK":
                require(self.pending is None and self.cleanup is None
                        and payload["index"] == len(self.chunks), "BROKER_CHUNK_ORDER")
                chunk = _base64_bytes(payload["dataBase64"], 24576)
                require(self.receipt_size + len(chunk) <= 4194304, "BROKER_RECEIPT_SIZE")
                self.chunks.append(chunk)
                self.receipt_size += len(chunk)
            elif kind == "CLEANUP_RECORDED":
                require(self.pending is None and self.chunks and self.cleanup is None
                        and (payload["state"] == "CLEAN") == (not payload["remainingResources"]),
                        "BROKER_CLEANUP_ORDER")
                seen = set()
                for row in payload["remainingResources"]:
                    key = (row["kind"], row["namespace"], row["name"])
                    require(key not in seen and row["manifestDigest"] in
                            self.binding["caseResourceDigests"][self.dispatch["caseId"]]
                            and (row["uid"] is not None or row["reasonCode"] == "IO_AMBIGUOUS"),
                            "BROKER_CLEANUP_SCOPE")
                    seen.add(key)
                self.cleanup = document(payload, 16384)
            elif kind == "TERMINAL":
                require(self.pending is None and self.cleanup is not None
                        and payload["receiptSize"] == self.receipt_size
                        and payload["receiptDigest"] == byte_digest(b"".join(self.chunks))
                        and payload["cleanupDigest"] == self.cleanup["cleanupDigest"],
                        "BROKER_TERMINAL_MISMATCH")
                require(payload["status"] != "COMPLETED" or
                        self.cleanup["state"] == "CLEAN" and not self.failed_action,
                        "BROKER_FALSE_COMPLETION")
                self.terminal = document(payload, 16384)
            elif kind != "STARTED":
                raise ConformanceError("BROKER_ABORTED", "execution refused; no success receipt")
            self.sequence, self.previous = frame["sequence"], canonical_digest(frame)
            return frame
        except BaseException:
            self.poisoned = True
            raise

    def server_frame(self, kind, payload):
        require(self.execution is not None, "BROKER_CONTROLLED_START_REQUIRED")
        frame = {"schemaVersion": "planeon.internal.broker-frame/v1",
                 **{k: self.dispatch[k] for k in BROKER_COMMON},
                 "executionId": self.execution, "sequence": self.sequence + 1,
                 "previousDigest": self.previous, "kind": kind, "payload": payload}
        self.accept(frame, "SERVER")
        return canonical_bytes(frame)

    def receipt(self):
        require(not self.poisoned and self.terminal is not None, "BROKER_TERMINAL_REQUIRED")
        return b"".join(self.chunks)


# Exact private schema data from MET-REPAIR-015. It cannot select a validator,
# import native code, open a file or create an execution/qualification handle.
_QUALIFICATION_SPEC = json.loads("{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:planeon:internal:native-qualification:v1\",\"oneOf\":[{\"$ref\":\"#/$defs/record\"},{\"$ref\":\"#/$defs/capture\"}],\"$defs\":{\"digest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"path\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":4096,\"pattern\":\"^/[A-Za-z0-9_./+-]+$\"},\"time\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":20,\"pattern\":\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$\"},\"scope\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"tenantId\",\"environmentId\",\"runNonce\",\"capacityNonce\",\"namespace\",\"validFrom\",\"expiresAt\"],\"properties\":{\"tenantId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"environmentId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"runNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"capacityNonce\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"namespace\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":253,\"pattern\":\"^[ -~]+$\"},\"validFrom\":{\"$ref\":\"#/$defs/time\"},\"expiresAt\":{\"$ref\":\"#/$defs/time\"}}},\"host\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"machine\",\"kernelRelease\",\"kernelNotesDigest\",\"bootId\"],\"properties\":{\"machine\":{\"enum\":[\"x86_64\",\"aarch64\"]},\"kernelRelease\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"kernelNotesDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"bootId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":36,\"pattern\":\"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\"}}},\"status\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"version\",\"sequence\",\"policyload\",\"enforcing\",\"denyUnknown\"],\"properties\":{\"version\":{\"const\":1},\"sequence\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4294967294},\"policyload\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4294967295},\"enforcing\":{\"const\":1},\"denyUnknown\":{\"const\":1}}},\"namespaces\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"user\",\"mnt\",\"pid\",\"net\"],\"properties\":{\"user\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"mnt\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"pid\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"net\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991}}},\"segment\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"offset\",\"length\",\"permissions\"],\"properties\":{\"offset\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"length\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":67108864},\"permissions\":{\"enum\":[\"r-xp\",\"r-xs\",\"--xp\",\"--xs\"]}}},\"file\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"mode\",\"size\",\"sha256\",\"verityDigest\",\"selinuxLabel\",\"executableSegments\"],\"properties\":{\"path\":{\"$ref\":\"#/$defs/path\"},\"mode\":{\"enum\":[\"0444\",\"0555\"]},\"size\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":67108864},\"sha256\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"verityDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"selinuxLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"executableSegments\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/segment\"},\"minItems\":0,\"maxItems\":16}}},\"program\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"programId\",\"programType\",\"translatedSha256\",\"instructionBytes\",\"mapIds\",\"ifindex\"],\"properties\":{\"programId\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4294967295},\"programType\":{\"enum\":[9,18]},\"translatedSha256\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"instructionBytes\":{\"type\":\"integer\",\"minimum\":8,\"maximum\":65536},\"mapIds\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"minItems\":0,\"maxItems\":0},\"ifindex\":{\"const\":0}}},\"cgroup\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"inode\",\"memoryMaxBytes\",\"pidsMax\",\"cpuQuotaMicros\",\"cpuPeriodMicros\"],\"properties\":{\"path\":{\"$ref\":\"#/$defs/path\"},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"memoryMaxBytes\":{\"type\":\"integer\",\"minimum\":1048576,\"maximum\":1099511627776},\"pidsMax\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096},\"cpuQuotaMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000},\"cpuPeriodMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000}}},\"fileObservation\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"entry\",\"device\",\"inode\",\"uid\",\"gid\",\"nlink\",\"contentDigest\",\"measuredVerity\"],\"properties\":{\"entry\":{\"$ref\":\"#/$defs/file\"},\"device\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"uid\":{\"const\":0},\"gid\":{\"const\":0},\"nlink\":{\"const\":1},\"contentDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"measuredVerity\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"}}},\"mapping\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"offset\",\"length\",\"permissions\",\"device\",\"inode\"],\"properties\":{\"path\":{\"$ref\":\"#/$defs/path\"},\"offset\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"length\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":67108864},\"permissions\":{\"enum\":[\"r-xp\",\"r-xs\",\"--xp\",\"--xs\"]},\"device\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991}}},\"observedProgram\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"program\",\"localIds\",\"effectiveIds\"],\"properties\":{\"program\":{\"$ref\":\"#/$defs/program\"},\"localIds\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"minItems\":1,\"maxItems\":16,\"uniqueItems\":true},\"effectiveIds\":{\"type\":\"array\",\"items\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"minItems\":1,\"maxItems\":16,\"uniqueItems\":true}}},\"record\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"schemaVersion\",\"qualificationProfile\",\"profileDigest\",\"scope\",\"host\",\"selinux\",\"roles\",\"files\",\"endpointTuples\"],\"properties\":{\"schemaVersion\":{\"const\":\"planeon.internal.native-qualification/v1\"},\"qualificationProfile\":{\"const\":\"SELINUX_FSVERITY_CGROUP_BPF_V1\"},\"profileDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"scope\":{\"$ref\":\"#/$defs/scope\"},\"host\":{\"$ref\":\"#/$defs/host\"},\"selinux\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"policyDigest\",\"status\"],\"properties\":{\"policyDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"status\":{\"$ref\":\"#/$defs/status\"}}},\"roles\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"SERVER\",\"OBSERVER\",\"BROKER\",\"WORKER\"],\"properties\":{\"SERVER\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"executable\",\"artifactDigest\",\"interpreterPath\",\"uid\",\"gid\",\"processLabel\",\"namespaceInodes\",\"cgroup\",\"seccompMode\",\"filePaths\",\"bpfPrograms\",\"outboundEndpointIds\"],\"properties\":{\"executable\":{\"const\":\"/opt/planeon/bin/harness-live-proxy-serve\"},\"artifactDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"interpreterPath\":{\"const\":\"/opt/planeon/python/3.12.14/bin/python3.12\"},\"uid\":{\"const\":0},\"gid\":{\"const\":0},\"processLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"namespaceInodes\":{\"$ref\":\"#/$defs/namespaces\"},\"cgroup\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"inode\",\"memoryMaxBytes\",\"pidsMax\",\"cpuQuotaMicros\",\"cpuPeriodMicros\"],\"properties\":{\"path\":{\"const\":\"/sys/fs/cgroup/planeon-live/proxy-server\"},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"memoryMaxBytes\":{\"type\":\"integer\",\"minimum\":1048576,\"maximum\":1099511627776},\"pidsMax\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096},\"cpuQuotaMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000},\"cpuPeriodMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000}}},\"seccompMode\":{\"const\":2},\"filePaths\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/path\"},\"minItems\":1,\"maxItems\":128,\"uniqueItems\":true},\"bpfPrograms\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"INET_SOCK_CREATE\",\"INET4_BIND\",\"INET6_BIND\",\"INET4_CONNECT\",\"INET6_CONNECT\",\"UDP4_SENDMSG\",\"UDP6_SENDMSG\"],\"properties\":{\"INET_SOCK_CREATE\":{\"$ref\":\"#/$defs/program\"},\"INET4_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET6_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET4_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"INET6_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"UDP4_SENDMSG\":{\"$ref\":\"#/$defs/program\"},\"UDP6_SENDMSG\":{\"$ref\":\"#/$defs/program\"}}},\"outboundEndpointIds\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"minItems\":0,\"maxItems\":16,\"uniqueItems\":true}}},\"OBSERVER\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"executable\",\"artifactDigest\",\"interpreterPath\",\"uid\",\"gid\",\"processLabel\",\"namespaceInodes\",\"cgroup\",\"seccompMode\",\"filePaths\",\"bpfPrograms\",\"outboundEndpointIds\"],\"properties\":{\"executable\":{\"const\":\"/opt/planeon/bin/harness-policy-observer\"},\"artifactDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"interpreterPath\":{\"const\":null},\"uid\":{\"const\":0},\"gid\":{\"const\":0},\"processLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"namespaceInodes\":{\"$ref\":\"#/$defs/namespaces\"},\"cgroup\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"inode\",\"memoryMaxBytes\",\"pidsMax\",\"cpuQuotaMicros\",\"cpuPeriodMicros\"],\"properties\":{\"path\":{\"const\":\"/sys/fs/cgroup/planeon-live/policy-observer\"},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"memoryMaxBytes\":{\"type\":\"integer\",\"minimum\":1048576,\"maximum\":1099511627776},\"pidsMax\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096},\"cpuQuotaMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000},\"cpuPeriodMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000}}},\"seccompMode\":{\"const\":2},\"filePaths\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/path\"},\"minItems\":1,\"maxItems\":128,\"uniqueItems\":true},\"bpfPrograms\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"INET_SOCK_CREATE\",\"INET4_BIND\",\"INET6_BIND\",\"INET4_CONNECT\",\"INET6_CONNECT\",\"UDP4_SENDMSG\",\"UDP6_SENDMSG\"],\"properties\":{\"INET_SOCK_CREATE\":{\"$ref\":\"#/$defs/program\"},\"INET4_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET6_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET4_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"INET6_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"UDP4_SENDMSG\":{\"$ref\":\"#/$defs/program\"},\"UDP6_SENDMSG\":{\"$ref\":\"#/$defs/program\"}}},\"outboundEndpointIds\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"minItems\":0,\"maxItems\":16,\"uniqueItems\":true}}},\"BROKER\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"executable\",\"artifactDigest\",\"interpreterPath\",\"uid\",\"gid\",\"processLabel\",\"namespaceInodes\",\"cgroup\",\"seccompMode\",\"filePaths\",\"bpfPrograms\",\"outboundEndpointIds\"],\"properties\":{\"executable\":{\"const\":\"/opt/planeon/bin/harness-capacity-broker\"},\"artifactDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"interpreterPath\":{\"const\":null},\"uid\":{\"const\":0},\"gid\":{\"const\":0},\"processLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"namespaceInodes\":{\"$ref\":\"#/$defs/namespaces\"},\"cgroup\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"inode\",\"memoryMaxBytes\",\"pidsMax\",\"cpuQuotaMicros\",\"cpuPeriodMicros\"],\"properties\":{\"path\":{\"const\":\"/sys/fs/cgroup/planeon-live/capacity-broker\"},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"memoryMaxBytes\":{\"type\":\"integer\",\"minimum\":1048576,\"maximum\":1099511627776},\"pidsMax\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096},\"cpuQuotaMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000},\"cpuPeriodMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000}}},\"seccompMode\":{\"const\":2},\"filePaths\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/path\"},\"minItems\":1,\"maxItems\":128,\"uniqueItems\":true},\"bpfPrograms\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"INET_SOCK_CREATE\",\"INET4_BIND\",\"INET6_BIND\",\"INET4_CONNECT\",\"INET6_CONNECT\",\"UDP4_SENDMSG\",\"UDP6_SENDMSG\"],\"properties\":{\"INET_SOCK_CREATE\":{\"$ref\":\"#/$defs/program\"},\"INET4_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET6_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET4_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"INET6_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"UDP4_SENDMSG\":{\"$ref\":\"#/$defs/program\"},\"UDP6_SENDMSG\":{\"$ref\":\"#/$defs/program\"}}},\"outboundEndpointIds\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"minItems\":0,\"maxItems\":16,\"uniqueItems\":true}}},\"WORKER\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"executable\",\"artifactDigest\",\"interpreterPath\",\"uid\",\"gid\",\"processLabel\",\"namespaceInodes\",\"cgroup\",\"seccompMode\",\"filePaths\",\"bpfPrograms\",\"outboundEndpointIds\"],\"properties\":{\"executable\":{\"const\":\"/opt/planeon/bin/harness-live-probe-exec\"},\"artifactDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"interpreterPath\":{\"const\":\"/opt/planeon/python/3.12.14/bin/python3.12\"},\"uid\":{\"type\":\"integer\",\"minimum\":10000,\"maximum\":2147483647},\"gid\":{\"type\":\"integer\",\"minimum\":10000,\"maximum\":2147483647},\"processLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"namespaceInodes\":{\"$ref\":\"#/$defs/namespaces\"},\"cgroup\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"path\",\"inode\",\"memoryMaxBytes\",\"pidsMax\",\"cpuQuotaMicros\",\"cpuPeriodMicros\"],\"properties\":{\"path\":{\"const\":\"/sys/fs/cgroup/planeon-live/probe-worker\"},\"inode\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"memoryMaxBytes\":{\"type\":\"integer\",\"minimum\":1048576,\"maximum\":1099511627776},\"pidsMax\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":4096},\"cpuQuotaMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000},\"cpuPeriodMicros\":{\"type\":\"integer\",\"minimum\":1000,\"maximum\":1000000}}},\"seccompMode\":{\"const\":2},\"filePaths\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/path\"},\"minItems\":1,\"maxItems\":128,\"uniqueItems\":true},\"bpfPrograms\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"INET_SOCK_CREATE\",\"INET4_BIND\",\"INET6_BIND\",\"INET4_CONNECT\",\"INET6_CONNECT\",\"UDP4_SENDMSG\",\"UDP6_SENDMSG\"],\"properties\":{\"INET_SOCK_CREATE\":{\"$ref\":\"#/$defs/program\"},\"INET4_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET6_BIND\":{\"$ref\":\"#/$defs/program\"},\"INET4_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"INET6_CONNECT\":{\"$ref\":\"#/$defs/program\"},\"UDP4_SENDMSG\":{\"$ref\":\"#/$defs/program\"},\"UDP6_SENDMSG\":{\"$ref\":\"#/$defs/program\"}}},\"outboundEndpointIds\":{\"type\":\"array\",\"items\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"minItems\":0,\"maxItems\":16,\"uniqueItems\":true}}}}},\"files\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/file\"},\"minItems\":4,\"maxItems\":128},\"endpointTuples\":{\"type\":\"array\",\"minItems\":1,\"maxItems\":16,\"items\":{\"$ref\":\"#/$defs/endpoint\"}}}},\"capture\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"evidenceClass\",\"qualificationDigest\",\"role\",\"host\",\"selinuxBefore\",\"selinuxAfter\",\"kernelPolicyDigest\",\"observedAt\",\"inspectionStartedMs\",\"inspectionFinishedMs\",\"deadlineMs\",\"process\",\"files\",\"executableMaps\",\"bpfPrograms\"],\"properties\":{\"evidenceClass\":{\"const\":\"DATA_CHECK_ONLY\"},\"qualificationDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"role\":{\"enum\":[\"SERVER\",\"OBSERVER\",\"BROKER\",\"WORKER\"]},\"host\":{\"$ref\":\"#/$defs/host\"},\"selinuxBefore\":{\"$ref\":\"#/$defs/status\"},\"selinuxAfter\":{\"$ref\":\"#/$defs/status\"},\"kernelPolicyDigest\":{\"type\":\"string\",\"pattern\":\"^sha256:[0-9a-f]{64}$\"},\"observedAt\":{\"$ref\":\"#/$defs/time\"},\"inspectionStartedMs\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"inspectionFinishedMs\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"deadlineMs\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":9007199254740991},\"process\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"pid\",\"startTicks\",\"uid\",\"gid\",\"processLabel\",\"namespaceInodes\",\"cgroup\",\"seccompMode\"],\"properties\":{\"pid\":{\"type\":\"integer\",\"minimum\":2,\"maximum\":2147483647},\"startTicks\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":9007199254740991},\"uid\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":2147483647},\"gid\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":2147483647},\"processLabel\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":256,\"pattern\":\"^[ -~]+$\"},\"namespaceInodes\":{\"$ref\":\"#/$defs/namespaces\"},\"cgroup\":{\"$ref\":\"#/$defs/cgroup\"},\"seccompMode\":{\"const\":2}}},\"files\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/fileObservation\"},\"minItems\":1,\"maxItems\":128},\"executableMaps\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/mapping\"},\"minItems\":1,\"maxItems\":256},\"bpfPrograms\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"INET_SOCK_CREATE\",\"INET4_BIND\",\"INET6_BIND\",\"INET4_CONNECT\",\"INET6_CONNECT\",\"UDP4_SENDMSG\",\"UDP6_SENDMSG\"],\"properties\":{\"INET_SOCK_CREATE\":{\"$ref\":\"#/$defs/observedProgram\"},\"INET4_BIND\":{\"$ref\":\"#/$defs/observedProgram\"},\"INET6_BIND\":{\"$ref\":\"#/$defs/observedProgram\"},\"INET4_CONNECT\":{\"$ref\":\"#/$defs/observedProgram\"},\"INET6_CONNECT\":{\"$ref\":\"#/$defs/observedProgram\"},\"UDP4_SENDMSG\":{\"$ref\":\"#/$defs/observedProgram\"},\"UDP6_SENDMSG\":{\"$ref\":\"#/$defs/observedProgram\"}}}}},\"endpoint\":{\"type\":\"object\",\"additionalProperties\":false,\"required\":[\"endpointId\",\"kind\",\"addressFamily\",\"ipAddress\",\"port\"],\"properties\":{\"endpointId\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":128,\"pattern\":\"^[ -~]+$\"},\"kind\":{\"enum\":[\"CAMPAIGN_PROXY\",\"KUBERNETES_API_PROXY\"]},\"addressFamily\":{\"enum\":[\"IPV4\",\"IPV6\"]},\"ipAddress\":{\"type\":\"string\",\"minLength\":1,\"maxLength\":45},\"port\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535}}}}}")
QUALIFICATION_PATH = "campaigns/platform/linux-baseline/native-qualification.json"


def _qualification_document(value, variant):
    require(variant in ("record", "capture"), "QUALIFICATION_VARIANT_INVALID")
    value = document(value)
    # Closed ASCII records exclude hidden controls in both keys and values.
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            require(all(32 <= ord(c) <= 126 for c in item), "QUALIFICATION_ASCII_REQUIRED")
        elif type(item) is dict:
            pending.extend(item)
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    _shape(value, _QUALIFICATION_SPEC["$defs"][variant], _QUALIFICATION_SPEC["$defs"])
    return value


def _canonical_qualification_path(value):
    require(type(value) is str and value.startswith("/") and "\\" not in value
            and len(value.split("/")) <= 65
            and all(part not in ("", ".", "..") for part in value[1:].split("/")),
            "QUALIFICATION_PATH_INVALID")


def validate_qualification_record(value, profile, endpoints):
    """Return detached EXPECTED data only, never native qualification authority.

    Inputs must already belong to independently verified retained authority for
    production use. This function performs no I/O, signs nothing and deliberately
    cannot create the private installed inspector or any of its owned handles.
    """
    record = _qualification_document(value, "record")
    profile = validate_profile(profile)
    scope = profile["binding"]
    require(record["profileDigest"] == canonical_digest(profile)
            and record["scope"] == {key: scope[key] for key in record["scope"]},
            "QUALIFICATION_PROFILE_SCOPE")
    require(record["selinux"]["status"]["sequence"] % 2 == 0, "QUALIFICATION_POLICY_EPOCH")
    fields = ("endpointId", "kind", "addressFamily", "ipAddress", "port")
    require(type(endpoints) is list and 1 <= len(endpoints) <= 16, "QUALIFICATION_ENDPOINTS")
    tuples = []
    for endpoint in endpoints:
        require(type(endpoint) is dict and set(fields) == set(endpoint), "QUALIFICATION_ENDPOINTS")
        row = {key: endpoint[key] for key in fields}
        _shape(row, _QUALIFICATION_SPEC["$defs"]["endpoint"], _QUALIFICATION_SPEC["$defs"])
        try:
            address = ipaddress.ip_address(row["ipAddress"])
        except ValueError as exc:
            raise ConformanceError("QUALIFICATION_ENDPOINTS", "numeric address required") from exc
        require(str(address) == row["ipAddress"] and not address.is_unspecified and not address.is_multicast
                and not (address.version == 6 and (address.ipv4_mapped is not None or address.scope_id is not None))
                and row["addressFamily"] ==
                ("IPV4" if address.version == 4 else "IPV6"), "QUALIFICATION_ENDPOINTS")
        tuples.append(row)
    require(len({row["endpointId"] for row in tuples}) == len(tuples)
            and record["endpointTuples"] == tuples, "QUALIFICATION_ENDPOINTS")
    expected_endpoints = {scope["endpointId"]: "CAMPAIGN_PROXY"}
    if profile["resources"]:
        expected_endpoints[scope["apiEndpointId"]] = "KUBERNETES_API_PROXY"
    require(expected_endpoints.items() <= {row["endpointId"]: row["kind"] for row in tuples}.items(),
            "QUALIFICATION_ENDPOINT_SCOPE")
    files = {row["path"]: row for row in record["files"]}
    require(len(files) == len(record["files"])
            and sum(row["size"] for row in files.values()) <= 536870912, "QUALIFICATION_FILE_INVENTORY")
    for row in files.values():
        _canonical_qualification_path(row["path"])
        require(row["sha256"] != row["verityDigest"], "QUALIFICATION_CONFLATED_DIGEST")
        segments = row["executableSegments"]
        seen = set()
        for segment in segments:
            identity = (segment["offset"], segment["length"], segment["permissions"])
            # The approved profile uses a 4096-byte segment-accounting boundary.
            # The native reader must separately compare actual ELF PT_LOAD.
            require(identity not in seen and segment["offset"] < row["size"]
                    and segment["offset"] + segment["length"] <= ((row["size"] + 4095) // 4096) * 4096,
                    "QUALIFICATION_SEGMENT_INVALID")
            seen.add(identity)
    used = set()
    for name, role in record["roles"].items():
        _canonical_qualification_path(role["cgroup"]["path"])
        selected = set(role["filePaths"])
        require(selected <= files.keys() and role["executable"] in selected,
                "QUALIFICATION_ROLE_FILES")
        artifact = files[role["executable"]]
        require(artifact["sha256"] == role["artifactDigest"] and artifact["mode"] == "0555",
                "QUALIFICATION_ARTIFACT_MISMATCH")
        if role["interpreterPath"] is not None:
            require(role["interpreterPath"] in selected
                    and files[role["interpreterPath"]]["mode"] == "0555"
                    and files[role["interpreterPath"]]["executableSegments"], "QUALIFICATION_INTERPRETER")
        else:
            require(artifact["executableSegments"], "QUALIFICATION_NATIVE_ELF_REQUIRED")
        used.update(selected)
        require(set(role["outboundEndpointIds"]) <= {row["endpointId"] for row in tuples},
                "QUALIFICATION_OUTBOUND_SCOPE")
        if name == "WORKER":
            require(not role["outboundEndpointIds"], "QUALIFICATION_WORKER_NETWORK")
        if name == "SERVER":
            require(role["outboundEndpointIds"] == ([scope["apiEndpointId"]] if profile["resources"] else []),
                    "QUALIFICATION_OUTBOUND_SCOPE")
        for hook, program in role["bpfPrograms"].items():
            require(program["programType"] == (9 if hook == "INET_SOCK_CREATE" else 18)
                    and program["instructionBytes"] % 8 == 0, "QUALIFICATION_PROGRAM_INVALID")
    require(used == files.keys(), "QUALIFICATION_UNUSED_FILE")
    return record


def retained_qualification_record(profile, endpoints, observation_binding, release, kit):
    """Bind the one fixed record to retained release bytes, not a selected path."""
    raw = kit.get(QUALIFICATION_PATH)
    require(type(raw) is bytes and 0 < len(raw) <= 262144, "QUALIFICATION_RECORD_MISSING")
    rows = [row for row in release["tree"] if row["path"] == QUALIFICATION_PATH]
    require(rows == [{"path": QUALIFICATION_PATH, "mode": "0444", "size": len(raw),
                      "sha256": byte_digest(raw)}], "QUALIFICATION_RECORD_CUSTODY")
    require(observation_binding["enforcementPins"]["hostPreflightDigest"] == byte_digest(raw),
            "QUALIFICATION_PREFLIGHT_PIN")
    return validate_qualification_record(raw, profile, endpoints)


def validate_qualification_capture(record, capture, profile, endpoints, *, role, previous=None):
    """Data-only cross-check for fixtures/diagnostics; returns None, not a grant.

    An attacker can manufacture matching data. The native inspector must obtain
    its own retained kernel observations and cannot accept this capture as input.
    """
    record = validate_qualification_record(record, profile, endpoints)
    capture = _qualification_document(capture, "capture")
    require(type(role) is str and role in record["roles"] and capture["role"] == role
            and capture["qualificationDigest"] == byte_digest(canonical_bytes(record))
            and capture["host"] == record["host"], "QUALIFICATION_CAPTURE_BINDING")
    require(capture["selinuxBefore"] == capture["selinuxAfter"] == record["selinux"]["status"]
            and capture["kernelPolicyDigest"] == record["selinux"]["policyDigest"], "QUALIFICATION_POLICY_CHANGED")
    begin, end, deadline = (capture[k] for k in ("inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"))
    require(begin <= end < deadline and end - begin <= 2000 and deadline - begin <= 900000,
            "QUALIFICATION_INSPECTION_EXPIRED")
    now = _time(capture["observedAt"])
    require(_time(record["scope"]["validFrom"]) <= now < _time(record["scope"]["expiresAt"]),
            "QUALIFICATION_INSPECTION_EXPIRED")
    role_name, role = role, record["roles"][role]
    process = capture["process"]
    require(all(process[k] == role[k] for k in ("uid", "gid", "processLabel", "namespaceInodes", "cgroup", "seccompMode")),
            "QUALIFICATION_PROCESS_CHANGED")
    expected = {row["path"]: row for row in record["files"] if row["path"] in role["filePaths"]}
    actual = {row["entry"]["path"]: row for row in capture["files"]}
    require(len(actual) == len(capture["files"]) and actual.keys() == expected.keys(), "QUALIFICATION_FILE_INVENTORY")
    seen_inodes, mappings = set(), []
    for path, row in actual.items():
        identity = (row["device"], row["inode"])
        require(identity not in seen_inodes and row["entry"] == expected[path]
                and row["contentDigest"] == expected[path]["sha256"]
                and row["measuredVerity"] == expected[path]["verityDigest"], "QUALIFICATION_FILE_CHANGED")
        seen_inodes.add(identity)
        for segment in expected[path]["executableSegments"]:
            mappings.append({"path": path, **segment, "device": row["device"], "inode": row["inode"]})
    require(sorted(map(canonical_bytes, mappings)) == sorted(map(canonical_bytes, capture["executableMaps"])),
            "QUALIFICATION_MAPPING_CHANGED")
    for hook, observed in capture["bpfPrograms"].items():
        program = role["bpfPrograms"][hook]
        require(observed["program"] == program and observed["localIds"] == observed["effectiveIds"] == [program["programId"]],
                "QUALIFICATION_PROGRAM_CHANGED")
    if previous is not None:
        validate_qualification_capture(record, previous, profile, endpoints, role=role_name)
        for key in ("host", "process", "files", "executableMaps", "bpfPrograms", "selinuxBefore",
                    "selinuxAfter", "kernelPolicyDigest"):
            require(capture[key] == previous[key], "QUALIFICATION_RETAINED_IDENTITY_CHANGED")
        require(capture["inspectionStartedMs"] >= previous["inspectionFinishedMs"]
                and capture["observedAt"] >= previous["observedAt"]
                and capture["deadlineMs"] == previous["deadlineMs"], "QUALIFICATION_LIFETIME_CHANGED")
