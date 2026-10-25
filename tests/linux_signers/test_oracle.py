"""CONF-LINUX-002 D5a oracle: the `signers` disclosure on the CONF-LINUX-001 path (R12).

Written from the closed design (revision 4, PASS_FOR_BUILD, sha256
e857138a61759619930060d4f84ed42a2177ed196b1cdd81d71a939d4abdb050) and the R12 base
c17bcfe32df26eab13844b73f65666bb0fa4e0a0 only (MON-CL2-ORACLE-PATH). Every expected value is a design literal or an
embedded base digest. The module imports nothing from tests/linux_signers/. Its own v1alpha2 signer is built on the
base's tests/platform/linux_baseline/_fixtures.py (loaded by path under a distinct name) and the base crypto.py, and
signs the ORIGINAL v1alpha2 documents over the v2 domains (sections 3 and 5).

Stated limit (section 5 (e), SG3-4): the local schema interpreter does not assert `format`.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import re
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))  # as tests/alpha1/test_alpha1.py line 9 (section 5, SG1-11)

from harness_conformance import linux_readiness as lr  # noqa: E402
from harness_conformance import live  # noqa: E402
from harness_conformance import schema as schema_module  # noqa: E402
from harness_conformance.canonical import byte_digest, canonical_bytes, load_json  # noqa: E402
from harness_conformance.crypto import b64url_decode, b64url_encode, public_key, sign, signature_payload, verify  # noqa: E402
from harness_conformance.errors import ConformanceError  # noqa: E402

# Section 5 (SG1-11): the base fixture loaded by path under a distinct module name, as test_checkpoint_chain.py 18-21.
_BASE_SPEC = importlib.util.spec_from_file_location(
    "conf_linux_002_oracle_base_fixtures", ROOT / "tests/platform/linux_baseline/_fixtures.py")
BASE_FIXTURES = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(BASE_FIXTURES)

# ---------------------------------------------------------------------------------------------------------------
# Design literals.
# Section 3 (live.py additions, each ending /v1alpha2), section 4 (the $id and schemaVersion const move to v1alpha2),
# SG3-5 (the v2 domain constants asserted against literal strings). Reading: each v2 literal is its v1alpha1
# counterpart with the final version segment changed to v1alpha2.
ENVELOPE_SCHEMA_V2 = "harness.planeon.ai/live-campaign-execution-envelope/v1alpha2"
CAPACITY_SCHEMA_V2 = "harness.planeon.ai/live-capacity-authorization/v1alpha2"
ENVELOPE_DOMAIN_V2 = "planeon.harness-live-execution-envelope/v1alpha2"
CAPACITY_DOMAIN_V2 = "planeon.harness-live-capacity-authorization/v1alpha2"
SCHEMA_V2 = "harness.planeon.ai/linux-readiness-evidence/v1alpha2"  # section 3, verbatim
DOMAIN_V2 = "planeon.harness-linux-readiness-evidence/v1alpha2"
SIGNERS = ("INDEPENDENT_PRINCIPALS", "SINGLE_PRINCIPAL_SEPARATED_KEYS")  # section 3, verbatim
INDEPENDENT, SINGLE = SIGNERS
SINGLE_PRINCIPAL_OWNER = "single-principal"  # section 3, verbatim (MON-SG-5)
SIGNERS_PROPERTY = {"enum": ["INDEPENDENT_PRINCIPALS", "SINGLE_PRINCIPAL_SEPARATED_KEYS"]}  # section 4, verbatim
UNKNOWN_SIGNERS = "SHARED_SIGNING_PRINCIPAL"
OTHER = {INDEPENDENT: SINGLE, SINGLE: INDEPENDENT}

# Base v1alpha1 literals (live.py lines 15-18, linux_readiness.py lines 20-22 and 46).
ENVELOPE_SCHEMA_V1 = "harness.planeon.ai/live-campaign-execution-envelope/v1alpha1"
CAPACITY_SCHEMA_V1 = "harness.planeon.ai/live-capacity-authorization/v1alpha1"
ENVELOPE_DOMAIN_V1 = "planeon.harness-live-execution-envelope/v1alpha1"
CAPACITY_DOMAIN_V1 = "planeon.harness-live-capacity-authorization/v1alpha1"
SCHEMA_V1 = "harness.planeon.ai/linux-readiness-evidence/v1alpha1"
DOMAIN_V1 = "planeon.harness-linux-readiness-evidence/v1alpha1"
PLAN_SCHEMA_V1 = "harness.planeon.ai/linux-readiness-plan/v1alpha1"
RECORD_FIELDS_V1 = ("schemaVersion", "authority", "target", "sources", "images", "build", "preflightDigest",
                    "observedAt", "validUntil", "cases", "platformSignerKeyId", "tenantSignerKeyId",
                    "capacitySignerKeyId", "platformSignature", "tenantSignature", "capacitySignature")
RECORD_SIGNATURES = ("platformSignature", "tenantSignature", "capacitySignature")
BASE_OWNERS = ("platform-unit-owner", "tenant-unit-owner", "capacity-unit-owner")  # the base fixture's owners
ROLES = ("platform", "tenant", "capacity")
NOW = "2026-09-07T01:00:00Z"  # the base fixture's NOW
INSTANT = datetime(2026, 9, 7, 1, 0, tzinfo=timezone.utc)
OTHER_DIGEST = BASE_FIXTURES.digest("oracle-other")

# ---------------------------------------------------------------------------------------------------------------
# Embedded base literals, computed from the c17bcfe3 export.
BASE_SHA256 = {
    "tests/platform/linux_baseline/_fixtures.py": "579ff77d11e66776884ccf4a3343c417393767215b09abc5aacc1a19c10bcb7d",
    "schemas/v1alpha1/live-campaign-execution-envelope.schema.json":
        "d4720d28fd0cfb8f4979f8d1bb808c5244c6e8121c4a97b0303cfed033c4d1fd",
    "schemas/v1alpha1/live-capacity-authorization.schema.json":
        "196cafdba0cc168b8dbab7cb02aeda003b1b0cb2f0ae8e9b233b883629949235",
    "schemas/v1alpha1/linux-readiness-evidence.schema.json":
        "8f4cf17273b097e39420b2394be43259c9bea30b684a58bcdc739c60b5059c0e",
    "docs/live-backend/linux-boundary.md": "157a7733b5df9dddc656d086f54e585b1508ef161e6849cdcc54cebc0b1ed7b3",
}
BASE_SRC_FILES = {
    "__init__.py", "__main__.py", "acceptance.py", "build_backend.py", "campaign.py", "canonical.py", "cli.py",
    "crypto.py", "errors.py", "events.py", "evidence.py", "lifecycle.py", "linux_readiness.py", "live.py",
    "live_backend_authority.py", "live_launcher.py", "live_linux_boundary.py", "live_mutation_admission.py",
    "live_proxy_client.py", "live_proxy_server.py", "live_replay_store.py", "live_session.py", "live_supervisor.py",
    "models.py", "registry.py", "schema.py",
}
# sha256(line)[:16] for every line of the base live.py (text.split("\n"), 344 entries).
_BASE_LIVE_LINE_ROWS = (
    "a6284e6d3d43bdfb e3b0c44298fc1c14 52cdf12944e12bff de2abade832c8e35 f9e42ccd54cc9de1 9e89c22761b2ee75",
    "6d69f2ac09017b8a 063e3d97fbe5c738 e3b0c44298fc1c14 07c5cdfea4d1acef b33334e1a14e1be8 0f6fc741eb88d98b",
    "dfd726ae89bdb803 e3b0c44298fc1c14 1b36d8931f6f882c ddc16b64341b56db c7c4c16bde56f196 45953d4c15627dd5",
    "550837261982ac6f 8c2bf43893564618 d397a1b697791905 38c2a79e3c8fba6a 2281bbfcc45fd8e5 4d1a3f278db8e39e",
    "1328d702a4d76bfa 25fe6b76cb39337d b1d0106d946ee999 e3b0c44298fc1c14 a8ce2388f512b6ef e6be3c9ce27a60c3",
    "c49a41d7e44d0c93 426c526c45c5d183 3f5afa1b743741c2 c223d71700d7366b dc58c9a65d664375 ae72246801566629",
    "0c688245e326cb8e 34bc0b01f110f7be d10b36aa74a59bcf da98426c4acd2896 561e0fedea437640 dfa380581fb92c44",
    "19b47eda24d74e86 9581f5125e502e1e 13bf7c92c8f0ba30 d10b36aa74a59bcf 3c321d79bddf8080 1f8181f985a54c28",
    "6f407421527ed222 d10b36aa74a59bcf 2a1adf0f83e50fb2 7d76755ed9293499 e3b0c44298fc1c14 e3b0c44298fc1c14",
    "7c222f8b2865afc1 2ea95b1dc051902a 1ff7935f10da0574 76e0e784e03b4dfe b2c5cb6bf46a3452 c2068cde533c4949",
    "23233b77f793cc03 e3b0c44298fc1c14 e3b0c44298fc1c14 641c399ad4ecc3e7 324fa537436e7708 e3b0c44298fc1c14",
    "e3b0c44298fc1c14 a17e281b08c7a1c7 b42cd938eff7c8e5 ccbeee8ea4eee5f0 d425c0b46007647b df733c26ce538e8b",
    "f8998730a591b768 aee45f1447705b56 f5f7ba44f93c988c fd8f417bde27bca7 7d553ed9c51e2074 a2d7eff354bd75a2",
    "b40c898c948fa278 50e1b307b84c4afd a9debb206f43616a e3b0c44298fc1c14 e3b0c44298fc1c14 6ac7fe9ebc53400e",
    "b9661744b25aa22f df6578c12cddcbf5 e05bbf1f9e4169ae 65608055289528d4 9f14d6dd28bac7c9 ff05fae2c45fb611",
    "da0efd84b01530cb c94f2f6f372b7580 ffc538db801cf75e f45dd3f4ba197a9f d0571587b5a75c1b 2b4894364d026892",
    "72fc23a4073a3e25 cdd03571cf22948d a8d4b5ad69d816f8 0c7e8f3285dae279 417e6084d89dcf11 c55ac09f39f3a2e1",
    "0024a2d49a3d96b9 2d1bf57d32cf0d8e 67ac3a623fa9dbbe 5c3747f74e53d9fb cb2adf023ac312a0 c4ed59c78aecc244",
    "165a74b74539e590 c09a3bf0431558b7 e3b0c44298fc1c14 e3b0c44298fc1c14 913e87edec217ce6 820cc5da2f78f5e0",
    "9828a0494264c7c7 3ca2d0cda03de5c3 142e34f76a5f84ad d5098daab1e193b2 75d19a45ea527e46 1e9a3624b5898a4a",
    "e553d0b8c9b781fe aa06fb5c712f2fd6 aca5dcd2c2bdb3dc df8c2f106ca1742e f657e9b699aa861c 20afec924f36999b",
    "627fc2329e1bd214 a6e8ba35603715d1 d3e7f2ec02614816 97dca74fa065cac7 bc91b8825affe793 1ef868cc860cc2da",
    "9ada5b5e6299e7a0 f412355fdc349036 145d8e483763a17f 5c72fa3549815586 e5d26b6f09a6f9c3 92fa53d4f31b96c6",
    "28d170db0d217a97 c313eb5774e2654b 0b38769bc2f68ca3 d920b321e65d7b05 0a0a426aabd1c934 fa59e75333c3d3de",
    "364b977a6f6e9b5f 0ea95b0ba232c4e0 45a6eee1c20d95da c048328a626670dd c81db0868366789a 51027ecfd5209b96",
    "a1842bc09b890184 32ba3c7c3b8a9c04 e3b0c44298fc1c14 e3b0c44298fc1c14 e5adc117efa9f516 f73dc3d2cdc83ca5",
    "80b4310b771dac3c 16c4d1c7b4b87e4f ad21041b707c9136 7130ca7adc04a271 349e263aac1fb437 bbce92a1bfacc7f1",
    "ef22dcfb7f488005 644b9058300d6462 f493f83511b11ebe 03c42aa8bbba0ef3 28d86778615f6af4 1d836ebbd97176c2",
    "e4cd736b4cad2b35 a5e7cdb85a178cd3 a79f970359965f4c 1026e2239b8b59c5 57c5130acd44db8b befa019c9a5f58f4",
    "2345ed2b60d2e321 cae6ef1a49834500 f8bee9f7252d4ee8 56ee4bc11e668a41 17e0780a726cb461 237f76d0f0d3ed75",
    "cd9c6642f3aebee6 f9aae1130f518c70 9279beaac8b0bd82 3942b8c5277d3b66 e3b0c44298fc1c14 e3b0c44298fc1c14",
    "9404a009bae8cb48 6ba481014b11c00e 8a35b9202242eb7e a5e58147b02b5493 baee5e883502511c 4dd1ae573be94497",
    "8f7c868696b21726 56d7c2581137da6e 0588f01df5e21f32 81fcb8ef7fb0cdd2 a42a7bea731a3862 4a3f134c53512a66",
    "b0bb5214cd1f3fe4 2f471396ad9fa68c 43880fd13e2f9d7f 6b6c8860a2caa51e 6497aa067a2c4a5e fdafb7f7680911a8",
    "e3b0c44298fc1c14 e3b0c44298fc1c14 d237a58eb678592e 4377b32e342db8db 2e214ed8f707d35c 513d6a195785bffa",
    "7226af15c8d9e675 6b3b169f992b5e3d 7525b06cbdf24077 22c3b437f38dd5f8 ae156cd4aacc5997 46a7d97ae57b4689",
    "abf0e16f1aa70449 92e2cab7336781eb a9c7ec1c97e64dd3 a46ea4f4a1ec623d e3b0c44298fc1c14 e3b0c44298fc1c14",
    "0c9aea371e5ce9f3 695ce728ab185736 34ec4ffb8f393da9 5aa0b288234ecbd2 7a958c8201b2a32b eac3a4c69e2105f7",
    "fb9e59671cc6d051 cabc1b08e0cb86d6 3a8c44abbf4ecce3 a36c3b99533305c4 47a836682c96885a 386e6864f7195679",
    "e03406a50cbbecef a36c3b99533305c4 6f482e0ae0e367f3 29e847adc9fd1c01 a96a95ffda369d4c 4991cc1ac48bc260",
    "8874fdb62270cfda d3da3020d2b65bef 8feb12fb378d78a7 37db44b36c2829f0 33e3290b64b32fa8 9c744bff53223a01",
    "1588859b234b6bd7 69585672cb55f628 e3b0c44298fc1c14 e3b0c44298fc1c14 ad561067a6c281ac c00868f46e79a599",
    "5cffd37832ba940f ddb7ee205b71d2d6 3060304b0e100813 e3b0c44298fc1c14 e3b0c44298fc1c14 aee03b96efb41935",
    "01b9d21427bb7c95 165645c85ea11a01 e6202a01650d44bf dd65eab6e2ad2485 5554b72400cf8b5a ad783458d6df4c65",
    "a85ecf6e6f9ad606 0a0a426aabd1c934 cac97e970b43893d 41d4f2919a7dd01c c0c4fe2f3d6888d1 e348099675f71584",
    "095f6ddfba862e35 2db8fa1bebd5a5e6 b93a1825df6712b3 774cc8a174dd31bc bebcbe0c57b937c9 f01aa6f92ae8f96a",
    "6b8b390c7531b815 68ee69c09711a049 eb2872b7e9b48638 64e1b2ec3d06603d 4cfba1d83a3e8b92 5069d962f7c6e92c",
    "d0ed3e192847c302 f417265e36582473 4f843073e8f30bf6 a023edeb25c73ce1 0b1b85475eda4153 f7dafd33a324f4c8",
    "28d86778615f6af4 e3b0c44298fc1c14 e3b0c44298fc1c14 ce1d9f36e2023ef7 4050f85be499e29b c6a4b17d3e08ec1f",
    "00bba973476bae91 2c9f09ec0d109699 cbab3238c37935d5 9786117824cf5551 e3b0c44298fc1c14 c94f2f6f372b7580",
    "72730c7059bbffdb 2c027b95664f0edc a18b5b2cf9d1c7ce 40f041ef486c0fc4 7029e23dce229185 0960cdcf06e54f10",
    "ea76796a97113bdd ed0738a01aaedb5d 2e7c39fbd844c891 dccf74668513cca6 6776b83d69eb65b1 35a82af356b51bf2",
    "8811d7b5fb41223c ece1d20e272a61cc 53c4d439ec686c92 4337dec00e15bb45 470bdc3a779d0dbf 3013b945ffb227b8",
    "c3d60ffe20fee3e7 88eff63a60069947 e5c8c09c10902474 983dd02467390201 ff6de0c9cb157ff0 c3dc664cebcd1bd4",
    "73650c863b1d79db 60b293deac8c63dc f36f607ba0802dd0 444d4837853dcbca bfb85df1123a37c9 970ce6c7ce00a21d",
    "6f65a3f034945984 9373621f5a1b0804 0e807234d7b7b222 11258f5920e6a93f c76b537a831a0b6f 91177092966df9f3",
    "9b95f5d84c974fd1 58b648554e692125 1147ec29fb1f858e decf08a2c79cebe7 3ecc4ec319add1d8 7aeeec7c5e610b72",
    "cd4508e1b9736c1a e3b0c44298fc1c14",
)
BASE_LIVE_LINE_DIGESTS = " ".join(_BASE_LIVE_LINE_ROWS).split()
# sha256 of each named top-level statement's source (decorators included; several statements joined by a blank line).
BASE_LIVE_NODES = {
    "ENVELOPE_FIELDS": "f87b3da05d7b825ff045dd63ce1979b1eef06205cd399efa5bf6ebcd28c1782e",
    "CAPACITY_FIELDS": "b3f359814cd12506d75ea2d3f3c1ae28cd6108871faaf632f887f74248e2b9cc",
    "validate_endpoint": "ec1f04153b1106e06c1a9e77edc01c7329695c37356c41d58a785f1d35a61bd8",
    "validate_envelope": "fc67eb26937023b01cbd4184240a51bb1beab919d02465b46c30db2f459ca157",
    "validate_capacity": "32538741b816be47631432355f309203617b47d596f54f3db1423afb09edc583",
    "_trust_key": "b31c07c525198cc737ca4ef7dfb99772776f95071ce577aee5ea12d1469a41c0",
    "verify_live_signatures": "d02c3b795eaff215fd524495b971d08630fec8be3ac8d40d35bfc4c0f8d61919",
    "preflight": "940cf95bd09eb932a0d557a650aa803f0f37ccc529c436be63eee8cd3dc296c6",
    "verify_linux_authority": "bfe8ec48ab380795be983e3c0c9f72768587d0e809e00e3485e76cf3c548faad",
}
BASE_LR_NODES = {
    "SCHEMA": "f48cfc242fe3b6eba893d91eaf6f5bb190cbc230b38775a439a134a79271a886",
    "PLAN_SCHEMA": "6d00f55c931a873524093de42b7ff18f13e89632559d76e48fb118a6a116bdf4",
    "DOMAIN": "c1e765360228dff930484fc155a1a70fdbad52bce60f050b9c0c1efcff49850e",
    "PACKET_DIGEST": "9867826c4b549549d93535e62ca9e00dd4dffc2de94869aa6e501a727a979277",
    "AXES": "d415684a304eb654579a6b8a45506e9ebfa2318db9367ebd27b049ee7f8e5279",
    "ARCHITECTURES": "64bf9043072d484929b2be60229ed082571f0c396ec79d9e67869d71c72230b2",
    "CASE_CHECKS": "03faef73b6f4a287fe2e1a4c08c68261e8cf472135b3eecdcbcb69071be0f231",
    "CASES": "eb10ac24fa7d25bc62f30936f04815ff5762e9bcc69fa6c276cda8a8d2bb6844",
    "CASE_AXES": "e1e850e3aa6381bfb4396d905526466f1b2e6a189ad85c1fb5d8324247e0c478",
    "REPOSITORIES": "af9e7605dc52b7f86b566df9a516b23cce44339db0b294adf6554a062ee93162",
    "IMAGES": "a50586845eb49b011c7957fcbd0239b487d1890654251f81dec9600f10b5a38a",
    "BUILD_FIELDS": "4e7d20be35b1ec7063bbc93427899a5b0e316cd1ecd545aa384f6e47c5ace892",
    "SIGNATURES": "c43d6af734faf5b4465652038defbb487836559f1ff484dfd387073cac8583fd",
    "AUTHORITY_FIELDS": "3fad8532c575c6ef83dab85e2f39e6e9a1f60e6c4d3f05d49e2821cb465b2c10",
    "RECORD_FIELDS": "9358a610c02b5027d61e5e5ccf9a4b8e9d94cd6c9c6c25a3475c8f4340740b4f",
    "STATUSES": "128f7bebe6cfeabc211a42604b000bfe4162cf7ca22fecae428fa5d652b3e1e1",
    "COMMANDS": "da2ccbd78c4b374b34af60a5d8c2a7c69238238a72349304688ac8a0751e4ea3",
    "require": "284eb5715971fdd2fd4e8c064ee8157ab0f13e583bc2dd53dd341e4d075fe753",
    "malformed_boundary": "75de2c6a99fdc97023eeec25d838afeeb7ca1479e8b4dafa4f28108ef3a840c4",
    "obj": "a84ba989268f9d19a3caf79d6caa6127252df228f3d795edf8d1a63f7a041cec",
    "require_time": "ab95b304b24cbc1e5138a07bd7bbd65bdd777c746e475cd10ff7b03373521773",
    "text": "39f3842ed9ce6d247c5069413259cb7c821ead0a4df47fad45ea5c70a7956c54",
    "integer": "5e3ad58e5b17b32a59af1a3a29fb3947d269e6ca11369e5a4883b6fbf76b9c25",
    "digest_map": "d1f5eb7e88cfd74f423d1322c96be8e53933db246608a5cfbba0bac6ca39073c",
    "sources": "c7e6b76c95b6572195ea6d30c26f582d3a180805427313c6d2703346f55bcb75",
    "target": "4fbf7a3d525a85dfd0edc5d46c596e61b0905d10925f5b4cb8b20e740360adba",
    "validate_plan": "d1538a4efc604f5c5dba25c671540cbc70c42ca9893fed3722bce4801edd5ef2",
    "validate_control_input": "d74eea3f8322ff2d8291bf141213e6dfab5f43897d9ea3a046e79bbbd17e88d7",
    "validate_linux_campaign": "8cd9cbff36d6f015fca35f1cb75d48b7dd1b04c478374fa8048ceafc74fcd1d5",
    "_overall": "a650dd3abffad3512c5d16be7f15951620688ac899037325fa5abc614738f2d7",
    "validate_linux_evidence": "8a8b70c3a62f111734d86d36d98605334da966260da132ff2c1910a061db5a36",
    "_release_plan": "934021dc81b9328c822101ca1c8fe2946c866c2da42ecdecc019cc0622fe50af",
    "build_probe_request": "c1e489afc04f51e4d8e83186782317875a98563e1cce4813e211af50609faf32",
    "evaluate_control": "2fec97423e62752dc92c84c15ef1eb5d74408e546683f2a98639fa09f29f92f7",
}
BASE_LR_TOP_IMPORTS = [
    ("from", "__future__", 0, (("annotations", None),)),
    ("import", None, 0, (("re", None),)),
    ("from", "functools", 0, (("wraps", None),)),
    ("from", "datetime", 0, (("timedelta", None),)),
    ("from", "typing", 0, (("Any", None),)),
    ("from", "canonical", 1, (("byte_digest", None), ("canonical_bytes", None), ("canonical_digest", None),
                              ("require_canonical_document", None))),
    ("from", "crypto", 1, (("b64url_decode", None), ("signature_payload", None), ("verify", None))),
    ("from", "errors", 1, (("ConformanceError", None),)),
    ("from", "schema", 1, (("closed", None), ("require_digest", None), ("require_id", None), ("require_key_id", None),
                           ("require_object", None), ("require_time", "parse_time"))),
]
# tests/platform/linux_baseline/test_linux_inventory.py lines 76-86.
LR_FORBIDDEN_MODULES = {"subprocess", "socket", "os", "pathlib", "requests", "urllib", "http", "ctypes",
                        "multiprocessing"}
FORBIDDEN_CALLS = {"open", "exec", "eval", "__import__", "compile"}
# ci/zero_bill.py lines 12-15.
ZERO_BILL_SOURCE_FORBIDDEN = ("import requests", "import urllib", "boto3", "google.cloud", "azure.identity",
                              "subprocess.run([\"curl\"", "subprocess.run([\"wget\"")
P_OR_K = inspect.Parameter.POSITIONAL_OR_KEYWORD
KW = inspect.Parameter.KEYWORD_ONLY
BASE_VERIFY_LINUX_EVIDENCE_PARAMETERS = [
    ("record_bytes", P_OR_K), ("envelope_bytes", KW), ("capacity_bytes", KW), ("release_bytes", KW),
    ("plan_bytes", KW), ("release_trust_bytes", KW), ("tenant_trust_bytes", KW), ("now", KW),
    ("expected_nonce", KW), ("expected_tenant", KW), ("expected_environment", KW), ("expected_release", KW),
    ("replayed_nonces", KW),
]
BASE_VERIFY_LINUX_AUTHORITY_PARAMETERS = [
    ("envelope_bytes", P_OR_K), ("capacity_bytes", P_OR_K), ("release_trust_bytes", P_OR_K),
    ("tenant_trust_bytes", P_OR_K), ("now", KW),
]
SCHEMA_FILES = {
    "envelope": "live-campaign-execution-envelope.schema.json",
    "capacity": "live-capacity-authorization.schema.json",
    "evidence": "linux-readiness-evidence.schema.json",
}


# ---------------------------------------------------------------------------------------------------------------
# Source helpers (section 3's code rules, checked by ast on the subject's files at run time).
def source_text(relative):
    return (ROOT / relative).read_bytes().decode("utf-8")


def _names_of(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Assign):
        return {target.id for target in node.targets if isinstance(target, ast.Name)}
    if isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def node_digest(text, name):
    tree = ast.parse(text)
    lines = text.split("\n")
    parts = []
    for node in tree.body:
        if name in _names_of(node):
            start = min([node.lineno] + [item.lineno for item in getattr(node, "decorator_list", [])])
            parts.append("\n".join(lines[start - 1:node.end_lineno]))
    return hashlib.sha256("\n\n".join(parts).encode()).hexdigest() if parts else None


def top_level_imports(tree):
    result = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            result.append(("import", None, 0, tuple((alias.name, alias.asname) for alias in node.names)))
        elif isinstance(node, ast.ImportFrom):
            result.append(("from", node.module, node.level, tuple((alias.name, alias.asname) for alias in node.names)))
    return result


def absolute_import_tops(tree):
    tops = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            tops |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            tops.add((node.module or "").split(".")[0])
    return tops


def top_level_assignments(tree, name):
    return [node for node in tree.body if name in _names_of(node)]


def is_subsequence(expected, actual):
    position = 0
    for item in actual:
        if position < len(expected) and item == expected[position]:
            position += 1
    return position == len(expected)


# ---------------------------------------------------------------------------------------------------------------
# Section 5 (e): a test-local stdlib interpreter. A local copy of test_linux_protocol.py's schema_assert rules
# (lines 12-51), not an import of that module, adding `$ref` resolved within the same file's `$defs`, and
# `uniqueItems`. `format` is not asserted (a stated limit).
class SchemaReferenceError(Exception):
    """An unresolvable or external `$ref`: it fails the test and is never swallowed by an `if` branch."""


def resolve_reference(reference, root):
    prefix = "#/$defs/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise SchemaReferenceError("external or malformed $ref " + repr(reference))
    name = reference[len(prefix):]
    definitions = root.get("$defs")
    if not name or "/" in name or "~" in name or not isinstance(definitions, dict) or name not in definitions:
        raise SchemaReferenceError("unresolvable $ref " + repr(reference))
    return definitions[name]


def schema_assert(value, schema, root):
    if "$ref" in schema:
        schema_assert(value, resolve_reference(schema["$ref"], root), root)
    if "const" in schema:
        assert canonical_bytes(value) == canonical_bytes(schema["const"])
    if "enum" in schema:
        assert any(canonical_bytes(value) == canonical_bytes(item) for item in schema["enum"])
    if "type" in schema:
        assert type(value) is {"object": dict, "array": list, "integer": int, "string": str, "boolean": bool}[schema["type"]]
    for conditional in schema.get("allOf", []):
        if "if" in conditional:
            try:
                schema_assert(value, conditional["if"], root)
            except AssertionError:
                continue
            schema_assert(value, conditional["then"], root)
        else:
            schema_assert(value, conditional, root)
    if isinstance(value, dict):
        assert set(schema.get("required", [])) <= value.keys()
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            assert value.keys() <= properties.keys()
        for key in value.keys() & properties.keys():
            schema_assert(value[key], properties[key], root)
    if isinstance(value, list):
        assert schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000000)
        prefix = schema.get("prefixItems", [])
        if schema.get("items") is False:
            assert len(value) <= len(prefix)
        for item, definition in zip(value, prefix):
            schema_assert(item, definition, root)
        if isinstance(schema.get("items"), dict):
            for item in value[len(prefix):]:
                schema_assert(item, schema["items"], root)
        if schema.get("uniqueItems") is True:
            encoded = [canonical_bytes(item) for item in value]
            assert len(encoded) == len(set(encoded))
    if isinstance(value, str):
        assert schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10000000)
        if "pattern" in schema:
            assert re.search(schema["pattern"], value)
    if type(value) is int:
        assert schema.get("minimum", 0) <= value <= schema.get("maximum", 10000000)


def reference_uses(node, root):
    """Resolve every `$ref` use in a schema document and count them."""
    count = 0
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                resolve_reference(value, root)
                count += 1
            else:
                count += reference_uses(value, root)
    elif isinstance(node, list):
        for item in node:
            count += reference_uses(item, root)
    return count


def load_schema(version, kind):
    return load_json(ROOT / "schemas" / version / SCHEMA_FILES[kind])


# ---------------------------------------------------------------------------------------------------------------
# The oracle's own v1alpha2 signer, built on the base LinuxFixture (MON-CL2-ORACLE-PATH).
_CACHE = {}


def base_set():
    """A fresh copy of the unchanged base v1alpha1 fixture."""
    if "base" not in _CACHE:
        _CACHE["base"] = BASE_FIXTURES.LinuxFixture()
    return deepcopy(_CACHE["base"])


def verify_v1(fixture):
    return lr.verify_linux_evidence(canonical_bytes(fixture.record), **fixture.inputs())


def resign_v1(fixture):
    """Re-bind and re-sign a base fixture over the v1alpha1 domains (the re-binding rule on the v1alpha1 path)."""
    fixture.resign_authority()
    fixture.record["authority"] = fixture.bindings()
    fixture.resign_record()


class SignersSet:
    """A v1alpha2 envelope, capacity and record over the base fixture, each the ORIGINAL v1alpha2 document signed
    over its own v2 domain (sections 3 and 5). Every method states what it re-binds or re-signs."""

    def __init__(self, signers=INDEPENDENT, owners=None):
        self.v1 = base_set()
        self.seeds = dict(self.v1.seeds)
        self.plan = deepcopy(self.v1.plan)
        self.release = deepcopy(self.v1.release)
        self.release_trust = deepcopy(self.v1.release_trust)
        self.tenant_trust = deepcopy(self.v1.tenant_trust)
        if owners is None:
            owners = (SINGLE_PRINCIPAL_OWNER,) * 3 if signers == SINGLE else BASE_OWNERS
        self.set_owners(owners)
        self.capacity = dict(deepcopy(self.v1.capacity), schemaVersion=CAPACITY_SCHEMA_V2, signers=signers)
        self.envelope = dict(deepcopy(self.v1.envelope), schemaVersion=ENVELOPE_SCHEMA_V2, signers=signers)
        self.record = dict(deepcopy(self.v1.record), schemaVersion=SCHEMA_V2, signers=signers)
        self.resign_all()

    @classmethod
    def fresh(cls, signers=INDEPENDENT):
        key = ("set", signers)
        if key not in _CACHE:
            _CACHE[key] = cls(signers)
        return deepcopy(_CACHE[key])

    def key(self, role):
        if role == "platform":
            return self.release_trust["keys"][0]
        return self.tenant_trust["keys"][{"tenant": 0, "capacity": 1}[role]]

    def set_owners(self, owners):
        for role, owner in zip(ROLES, owners):
            self.key(role)["owner"] = owner

    def sign_capacity(self, domain=CAPACITY_DOMAIN_V2):
        payload = signature_payload(domain, self.capacity, ("signature",))
        self.capacity["signature"] = b64url_encode(sign(self.seeds["capacity"], payload))

    def bind_envelope(self):
        """Re-bind the envelope to the capacity and both trust bundles (no signature)."""
        self.envelope["capacityAuthorizationDigest"] = byte_digest(canonical_bytes(self.capacity))
        self.envelope["releaseTrustStoreDigest"] = byte_digest(canonical_bytes(self.release_trust))
        self.envelope["tenantTrustStoreDigest"] = byte_digest(canonical_bytes(self.tenant_trust))

    def sign_envelope(self, domain=ENVELOPE_DOMAIN_V2, roles=("platform", "tenant")):
        payload = signature_payload(domain, self.envelope, ("platformSignature", "tenantSignature"))
        for role in roles:
            self.envelope[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def bind_record(self):
        """Re-bind the record's authority.envelopeDigest and authority.capacityDigest (no signature)."""
        self.record["authority"]["envelopeDigest"] = byte_digest(canonical_bytes(self.envelope))
        self.record["authority"]["capacityDigest"] = byte_digest(canonical_bytes(self.capacity))

    def sign_record(self, domain=DOMAIN_V2):
        payload = signature_payload(domain, self.record, RECORD_SIGNATURES)
        for role in ROLES:
            self.record[role + "Signature"] = b64url_encode(sign(self.seeds[role], payload))

    def resign_envelope_and_record(self):
        """Re-sign the envelope, re-bind the record to it and re-sign the record (capacity untouched)."""
        self.sign_envelope()
        self.bind_record()
        self.sign_record()

    def resign_all(self):
        """Re-sign the capacity, re-bind and re-sign the envelope, re-bind and re-sign the record."""
        self.sign_capacity()
        self.bind_envelope()
        self.resign_envelope_and_record()

    def inputs(self):
        release_bytes = canonical_bytes(self.release)
        return {"envelope_bytes": canonical_bytes(self.envelope), "capacity_bytes": canonical_bytes(self.capacity),
                "release_bytes": release_bytes, "plan_bytes": canonical_bytes(self.plan),
                "release_trust_bytes": canonical_bytes(self.release_trust),
                "tenant_trust_bytes": canonical_bytes(self.tenant_trust), "now": NOW,
                "expected_nonce": "unit-run-nonce", "expected_tenant": "unit-tenant",
                "expected_environment": "unit-environment", "expected_release": byte_digest(release_bytes),
                "replayed_nonces": frozenset()}

    def verify(self):
        return lr.verify_linux_evidence(canonical_bytes(self.record), **self.inputs())

    def authority(self):
        return live.verify_linux_authority_v2(
            canonical_bytes(self.envelope), canonical_bytes(self.capacity), canonical_bytes(self.release_trust),
            canonical_bytes(self.tenant_trust), now=INSTANT)


def expected_result(record):
    """Section 3: 'the case checks and result, as today' (linux_readiness.py lines 304-307)."""
    return {"verificationStatus": "PASS", "evidenceDigest": byte_digest(canonical_bytes(record)), "architecture": "amd64",
            "caseResults": {case: "PASS" for case in lr.CASES}, "evidenceClass": "UNIT_VERIFICATION_ONLY",
            "nativeAcceptance": False}


def parameters(function):
    return [(item.name, item.kind) for item in inspect.signature(function).parameters.values()]


def _decode(value):
    return b64url_decode(value, expected_length=64)


class OracleCase(unittest.TestCase):
    maxDiff = 4000

    def assertReason(self, reason, function, *args, **kwargs):
        with self.assertRaises(ConformanceError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)


# ===============================================================================================================
class Test01Sg3BindingFirst(OracleCase):
    """SG3-1 and SG3-2, binding under the owner's cap (design-status.json bindingBuildRules): checked first."""

    def test_00_changed_capacity_not_rebound_meets_digest_mismatch(self):
        # SG3-1 (section 2): a changed capacity first fails LINUX_AUTHORITY_DIGEST_MISMATCH (live.py lines 309-312)
        # unless the envelope's digest of it is re-bound. Nothing is re-bound here (section 5's re-binding rule).
        for label, field, value, resign_capacity in (("signers", "signers", SINGLE, False),
                                                      ("signers, capacity re-signed", "signers", SINGLE, True),
                                                      ("limitRangeDigest", "limitRangeDigest", OTHER_DIGEST, False)):
            s = SignersSet.fresh(INDEPENDENT)
            s.capacity[field] = value
            if resign_capacity:
                s.sign_capacity()
            with self.subTest(label):
                self.assertReason("LINUX_AUTHORITY_DIGEST_MISMATCH", s.verify)

    def test_01_changed_trust_bundle_not_rebound_meets_digest_mismatch(self):
        # SG3-1 (section 2): a changed trust bundle first fails LINUX_AUTHORITY_DIGEST_MISMATCH. Nothing re-bound.
        s = SignersSet.fresh(INDEPENDENT)
        s.release_trust["revocationsDigest"] = OTHER_DIGEST
        self.assertReason("LINUX_AUTHORITY_DIGEST_MISMATCH", s.verify)
        s = SignersSet.fresh(SINGLE)
        s.key("capacity")["owner"] = "capacity-unit-owner"
        self.assertReason("LINUX_AUTHORITY_DIGEST_MISMATCH", s.verify)

    def test_02_rebound_capacity_or_trust_bundle_meets_the_signatures(self):
        # SG3-1 (section 2) with the re-binding rule (section 5): once the envelope's digest is re-bound, the change
        # meets the signature checks (live.py line 334).
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE
        s.sign_capacity()
        s.bind_envelope()  # re-bound; the envelope is NOT re-signed
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE  # capacity NOT re-signed
        s.bind_envelope()
        s.resign_envelope_and_record()  # envelope re-signed over ENVELOPE_DOMAIN_V2; record re-bound and re-signed
        self.assertReason("CAPACITY_SIGNATURE_INVALID", s.verify)
        s = SignersSet.fresh(INDEPENDENT)
        s.tenant_trust["revocationsDigest"] = OTHER_DIGEST
        s.bind_envelope()  # re-bound; the envelope is NOT re-signed
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_03_changed_envelope_meets_its_own_signature_whatever_is_rebound(self):
        # SG3-1 (section 2): a changed envelope fails PLATFORM_SIGNATURE_INVALID (live.py line 334 through
        # linux_readiness.py line 253), before the record's envelopeDigest is compared (line 276), whether or not
        # that digest is re-bound. The envelope is never re-signed here.
        for field, value in (("signers", SINGLE), ("launcherDigest", OTHER_DIGEST)):
            for mode in ("not re-bound", "re-bound", "re-bound and record re-signed"):
                s = SignersSet.fresh(INDEPENDENT)
                s.envelope[field] = value
                if mode != "not re-bound":
                    s.bind_record()
                if mode == "re-bound and record re-signed":
                    s.sign_record()
                with self.subTest(field=field, mode=mode):
                    self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_04_changed_record_meets_the_record_signature(self):
        # SG3-1 (section 2): a changed record is bound by no digest, so it fails LINUX_EVIDENCE_SIGNATURE_INVALID
        # (linux_readiness.py line 294). The record is not re-signed.
        for field, value in (("signers", SINGLE), ("validUntil", "2026-09-07T01:30:00Z")):
            s = SignersSet.fresh(INDEPENDENT)
            s.record[field] = value
            with self.subTest(field=field):
                self.assertReason("LINUX_EVIDENCE_SIGNATURE_INVALID", s.verify)

    def test_05_record_with_signers_under_v1alpha1_or_unknown_version_is_unknown_field(self):
        # SG3-2 (section 5, binding): a record carrying `signers` under v1alpha1 or an unknown schemaVersion takes
        # today's path and is refused UNKNOWN_FIELD (linux_readiness.py line 160) through verify_linux_evidence.
        for version in (SCHEMA_V1, "harness.planeon.ai/linux-readiness-evidence/v1alpha3",
                        "harness.planeon.ai/linux-readiness-evidence/v2"):
            s = SignersSet.fresh(INDEPENDENT)
            s.record["schemaVersion"] = version
            s.sign_record(DOMAIN_V1)  # re-signed over the v1alpha1 domain (today's path)
            with self.subTest(context="v1alpha2 envelope and capacity", version=version):
                self.assertReason("UNKNOWN_FIELD", s.verify)
            fixture = base_set()
            fixture.record["schemaVersion"] = version
            fixture.record["signers"] = INDEPENDENT
            fixture.resign_record()
            with self.subTest(context="v1alpha1 envelope and capacity", version=version):
                self.assertReason("UNKNOWN_FIELD", verify_v1, fixture)

    def test_06_direct_v2_record_validator_pins_its_defensive_version_check(self):
        # SG3-2 (sections 3 and 5): _validate_linux_evidence_v2 called directly on such a record:
        # LINUX_EVIDENCE_SCHEMA_INVALID.
        for version in (SCHEMA_V1, "harness.planeon.ai/linux-readiness-evidence/v1alpha3"):
            s = SignersSet.fresh(INDEPENDENT)
            s.record["schemaVersion"] = version
            s.sign_record(DOMAIN_V1)
            with self.subTest(version=version):
                self.assertReason("LINUX_EVIDENCE_SCHEMA_INVALID", lr._validate_linux_evidence_v2, s.record)


# ===============================================================================================================
class Test02Interface(OracleCase):
    """Section 3: the names, values and signatures the design gives."""

    def test_00_v2_constants_equal_the_design_literals(self):
        # Section 3; section 4; SG3-5 (the v2 domain constants against literal strings).
        self.assertEqual(live.ENVELOPE_SCHEMA_V2, "harness.planeon.ai/live-campaign-execution-envelope/v1alpha2")
        self.assertEqual(live.CAPACITY_SCHEMA_V2, "harness.planeon.ai/live-capacity-authorization/v1alpha2")
        self.assertEqual(live.ENVELOPE_DOMAIN_V2, "planeon.harness-live-execution-envelope/v1alpha2")
        self.assertEqual(live.CAPACITY_DOMAIN_V2, "planeon.harness-live-capacity-authorization/v1alpha2")
        self.assertEqual(lr.SCHEMA_V2, "harness.planeon.ai/linux-readiness-evidence/v1alpha2")
        self.assertEqual(lr.DOMAIN_V2, "planeon.harness-linux-readiness-evidence/v1alpha2")
        self.assertEqual(live.SIGNERS, ("INDEPENDENT_PRINCIPALS", "SINGLE_PRINCIPAL_SEPARATED_KEYS"))
        self.assertEqual(live.SINGLE_PRINCIPAL_OWNER, "single-principal")
        self.assertEqual(lr.RECORD_FIELDS_V2, (*RECORD_FIELDS_V1, "signers"))
        # The new domains keep a v1alpha1 signature from verifying over a v1alpha2 document (section 3).
        self.assertNotEqual(live.ENVELOPE_DOMAIN_V2, live.ENVELOPE_DOMAIN)
        self.assertNotEqual(live.CAPACITY_DOMAIN_V2, live.CAPACITY_DOMAIN)
        self.assertNotEqual(lr.DOMAIN_V2, lr.DOMAIN)

    def test_01_shared_constants_keep_their_v1alpha1_values(self):
        # Section 3 (MON-SG-2 (a)): ENVELOPE_SCHEMA, CAPACITY_SCHEMA and their domains stay exactly as they are.
        self.assertEqual(live.ENVELOPE_SCHEMA, ENVELOPE_SCHEMA_V1)
        self.assertEqual(live.CAPACITY_SCHEMA, CAPACITY_SCHEMA_V1)
        self.assertEqual(live.ENVELOPE_DOMAIN, ENVELOPE_DOMAIN_V1)
        self.assertEqual(live.CAPACITY_DOMAIN, CAPACITY_DOMAIN_V1)
        self.assertEqual(lr.SCHEMA, SCHEMA_V1)
        self.assertEqual(lr.DOMAIN, DOMAIN_V1)
        self.assertEqual(lr.PLAN_SCHEMA, PLAN_SCHEMA_V1)
        self.assertEqual(lr.RECORD_FIELDS, RECORD_FIELDS_V1)

    def test_02_v2_function_signatures(self):
        # Section 3: validate_envelope_v2(document, *, now); validate_capacity_v2(document, envelope_v2, *, now);
        # verify_live_signatures_v2(envelope_v2, capacity_v2, release_trust, tenant_trust, *, now);
        # verify_linux_authority_v2(...) with verify_linux_authority's parameters; _validate_linux_evidence_v2(value).
        # Reading: names and kinds are asserted; defaults are not.
        self.assertEqual(parameters(live.validate_envelope_v2), [("document", P_OR_K), ("now", KW)])
        self.assertEqual(parameters(live.validate_capacity_v2),
                         [("document", P_OR_K), ("envelope_v2", P_OR_K), ("now", KW)])
        self.assertEqual(parameters(live.verify_live_signatures_v2),
                         [("envelope_v2", P_OR_K), ("capacity_v2", P_OR_K), ("release_trust", P_OR_K),
                          ("tenant_trust", P_OR_K), ("now", KW)])
        self.assertEqual(parameters(live.verify_linux_authority_v2), BASE_VERIFY_LINUX_AUTHORITY_PARAMETERS)
        self.assertEqual(parameters(lr._validate_linux_evidence_v2), [("value", P_OR_K)])

    def test_03_shared_entry_point_signatures_are_unchanged(self):
        # Section 3: verify_linux_evidence keeps its signature (the dispatch is inside it); verify_linux_authority is
        # unchanged.
        self.assertEqual(parameters(lr.verify_linux_evidence), BASE_VERIFY_LINUX_EVIDENCE_PARAMETERS)
        self.assertEqual(parameters(live.verify_linux_authority), BASE_VERIFY_LINUX_AUTHORITY_PARAMETERS)

    def test_04_signers_and_label_defined_once_in_live(self):
        # Section 3 (SG1-5): SIGNERS and SINGLE_PRINCIPAL_OWNER are defined once, in live.py.
        live_tree = ast.parse(source_text("src/harness_conformance/live.py"))
        lr_tree = ast.parse(source_text("src/harness_conformance/linux_readiness.py"))
        for name in ("SIGNERS", "SINGLE_PRINCIPAL_OWNER"):
            with self.subTest(name=name):
                self.assertEqual(len(top_level_assignments(live_tree, name)), 1)
                self.assertEqual(top_level_assignments(lr_tree, name), [])

    def test_05_v2_record_validator_is_not_registered(self):
        # Section 3 (SG1-3 (a)): _validate_linux_evidence_v2 is not registered in schema.validate.
        self.assertEqual(set(schema_module.VALIDATORS), {"campaign", "environment-intake", "control-result",
                                                         "porting-ledger"})
        self.assertNotIn(lr._validate_linux_evidence_v2, set(schema_module.VALIDATORS.values()))


# ===============================================================================================================
class Test03OwnerRule(OracleCase):
    """Sections 2 and 5: the owner rule selected by the disclosure."""

    def owners_vector(self, signers, owners, reason):
        s = SignersSet(signers, owners)
        with self.subTest(signers=signers, owners=owners):
            self.assertReason(reason, s.verify)

    def test_00_single_principal_needs_three_reserved_labels(self):
        # Section 5: SINGLE_PRINCIPAL_SEPARATED_KEYS with owners two plus one, or three equal owners other than
        # single-principal: LINUX_SIGNER_OWNERS_NOT_SINGLE_PRINCIPAL. Section 2: a mixed set or any other shared value.
        label = SINGLE_PRINCIPAL_OWNER
        for owners in ((label, label, "capacity-unit-owner"), (label, "tenant-unit-owner", label),
                       ("platform-unit-owner", label, label), ("shared-unit-owner",) * 3, BASE_OWNERS):
            self.owners_vector(SINGLE, owners, "LINUX_SIGNER_OWNERS_NOT_SINGLE_PRINCIPAL")

    def test_01_single_principal_with_a_shared_public_key(self):
        # Section 5: the same with a shared public key: SIGNER_ROLES_NOT_INDEPENDENT. All documents re-signed.
        s = SignersSet.fresh(SINGLE)
        s.seeds["capacity"] = s.seeds["tenant"]
        s.key("capacity")["publicKey"] = b64url_encode(public_key(s.seeds["tenant"]))
        s.resign_all()
        self.assertReason("SIGNER_ROLES_NOT_INDEPENDENT", s.verify)

    def test_02_single_principal_with_equal_platform_and_tenant_key_ids(self):
        # Section 5: with equal platform and tenant key ids: SIGNER_ROLES_NOT_INDEPENDENT (live.py line 149).
        s = SignersSet.fresh(SINGLE)
        s.envelope["tenantSignerKeyId"] = s.envelope["platformSignerKeyId"]
        s.resign_envelope_and_record()
        self.assertReason("SIGNER_ROLES_NOT_INDEPENDENT", s.verify)

    def test_03_independent_principals_with_a_shared_owner(self):
        # Section 5: INDEPENDENT_PRINCIPALS with a shared owner: LINUX_SIGNER_OWNERS_NOT_INDEPENDENT.
        for owners in (("platform-unit-owner", "shared-unit-owner", "shared-unit-owner"),
                       ("shared-unit-owner", "tenant-unit-owner", "shared-unit-owner"),
                       ("shared-unit-owner",) * 3):
            self.owners_vector(INDEPENDENT, owners, "LINUX_SIGNER_OWNERS_NOT_INDEPENDENT")

    def test_04_independent_principals_refuse_the_reserved_label(self):
        # Section 5 (SG1-7): INDEPENDENT_PRINCIPALS with an owner equal to single-principal: LINUX_RESERVED_OWNER_LABEL.
        for index in range(3):
            owners = list(BASE_OWNERS)
            owners[index] = SINGLE_PRINCIPAL_OWNER
            self.owners_vector(INDEPENDENT, tuple(owners), "LINUX_RESERVED_OWNER_LABEL")

    def test_05_independent_checks_run_distinct_first(self):
        # Section 2 (SG2-3): the two INDEPENDENT_PRINCIPALS checks run in this order: pairwise distinct first.
        label = SINGLE_PRINCIPAL_OWNER
        self.owners_vector(INDEPENDENT, (label,) * 3, "LINUX_SIGNER_OWNERS_NOT_INDEPENDENT")
        self.owners_vector(INDEPENDENT, (label, label, "capacity-unit-owner"), "LINUX_SIGNER_OWNERS_NOT_INDEPENDENT")

    def test_06_missing_and_non_identifier_owners(self):
        # Section 5 (g) and section 2: a missing owner, MISSING_FIELD (live.py line 326); a non-identifier owner,
        # INVALID_IDENTIFIER (line 330). Trust bundle changed, envelope re-bound and re-signed, record re-bound and
        # re-signed.
        for signers in SIGNERS:
            for role in ROLES:
                s = SignersSet.fresh(signers)
                del s.key(role)["owner"]
                s.resign_all()
                with self.subTest(signers=signers, role=role, owner="missing"):
                    self.assertReason("MISSING_FIELD", s.verify)
                s = SignersSet.fresh(signers)
                s.key(role)["owner"] = "Single Principal"
                s.resign_all()
                with self.subTest(signers=signers, role=role, owner="non-identifier"):
                    self.assertReason("INVALID_IDENTIFIER", s.verify)

    def test_07_v1alpha1_owner_rule_stays_as_it_is(self):
        # Section 2: "The v1alpha1 path stays as it is": distinct owners required, no reserved-label rule there.
        fixture = base_set()
        fixture.release_trust["keys"][0]["owner"] = SINGLE_PRINCIPAL_OWNER
        resign_v1(fixture)
        self.assertEqual(verify_v1(fixture)["verificationStatus"], "PASS")
        for owners in ((SINGLE_PRINCIPAL_OWNER,) * 3, ("shared-unit-owner",) * 3):
            fixture = base_set()
            fixture.release_trust["keys"][0]["owner"] = owners[0]
            fixture.tenant_trust["keys"][0]["owner"] = owners[1]
            fixture.tenant_trust["keys"][1]["owner"] = owners[2]
            resign_v1(fixture)
            with self.subTest(owners=owners):
                self.assertReason("LINUX_SIGNER_OWNERS_NOT_INDEPENDENT", verify_v1, fixture)


# ===============================================================================================================
class Test04Disclosure(OracleCase):
    """Section 5: the disclosure vectors."""

    def test_00_disagreement_between_documents(self):
        # Section 5: envelope against capacity, envelope against record, and capacity against record, each properly
        # signed and re-bound: LINUX_SIGNERS_DISCLOSURE_MISMATCH (section 2).
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE
        s.resign_all()
        with self.subTest("envelope against capacity"):
            self.assertReason("LINUX_SIGNERS_DISCLOSURE_MISMATCH", s.verify)
            self.assertReason("LINUX_SIGNERS_DISCLOSURE_MISMATCH", s.authority)
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            s.record["signers"] = OTHER[signers]
            s.sign_record()
            with self.subTest("envelope against record", signers=signers):
                self.assertReason("LINUX_SIGNERS_DISCLOSURE_MISMATCH", s.verify)
        s = SignersSet.fresh(SINGLE)
        s.capacity["signers"] = INDEPENDENT  # envelope and record stay SINGLE_PRINCIPAL_SEPARATED_KEYS
        s.resign_all()
        with self.subTest("capacity against record"):
            self.assertReason("LINUX_SIGNERS_DISCLOSURE_MISMATCH", s.verify)

    def test_01_agreement_runs_before_the_owner_rule(self):
        # Section 3 (verify_linux_authority_v2): the signers agreement, then the owner rule. Owners that fail the
        # envelope's rule still meet LINUX_SIGNERS_DISCLOSURE_MISMATCH first.
        s = SignersSet(INDEPENDENT, BASE_OWNERS)
        s.envelope["signers"] = SINGLE
        s.record["signers"] = SINGLE
        s.resign_all()
        self.assertReason("LINUX_SIGNERS_DISCLOSURE_MISMATCH", s.verify)

    def test_02_unknown_value_in_each_document(self):
        # Section 5: an unknown value in the envelope, in the capacity and in the record: LINUX_SIGNERS_INVALID.
        for document in ("envelope", "capacity", "record"):
            s = SignersSet.fresh(INDEPENDENT)
            getattr(s, document)["signers"] = UNKNOWN_SIGNERS
            s.resign_all()
            with self.subTest(document=document):
                self.assertReason("LINUX_SIGNERS_INVALID", s.verify)

    def test_03_signers_missing_from_a_v2_document(self):
        # Section 5: signers missing from a v1alpha2 document: MISSING_FIELD.
        for document in ("envelope", "capacity", "record"):
            s = SignersSet.fresh(INDEPENDENT)
            del getattr(s, document)["signers"]
            s.resign_all()
            with self.subTest(document=document):
                self.assertReason("MISSING_FIELD", s.verify)

    def test_04_envelope_or_capacity_with_signers_under_another_version(self):
        # Section 5: an envelope or capacity carrying signers under a v1alpha1 or unknown schemaVersion on the
        # v1alpha2 path: UNSUPPORTED_ENVELOPE or UNSUPPORTED_CAPACITY.
        for version in (ENVELOPE_SCHEMA_V1, "harness.planeon.ai/live-campaign-execution-envelope/v1alpha3"):
            s = SignersSet.fresh(INDEPENDENT)
            s.envelope["schemaVersion"] = version
            s.resign_envelope_and_record()
            with self.subTest(document="envelope", version=version):
                self.assertReason("UNSUPPORTED_ENVELOPE", s.verify)
        for version in (CAPACITY_SCHEMA_V1, "harness.planeon.ai/live-capacity-authorization/v1alpha3"):
            s = SignersSet.fresh(INDEPENDENT)
            s.capacity["schemaVersion"] = version
            s.resign_all()
            with self.subTest(document="capacity", version=version):
                self.assertReason("UNSUPPORTED_CAPACITY", s.verify)


# ===============================================================================================================
class Test05Tampering(OracleCase):
    """Section 5 (a): tampering after signing (SG2-1, SG3-1)."""

    def test_00_envelope_alone_record_digest_rebound_nothing_resigned(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.envelope["signers"] = SINGLE
        s.bind_record()  # the record's envelopeDigest re-bound; nothing re-signed
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_01_capacity_alone_envelope_rebound_and_resigned(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE  # capacity not re-signed
        s.bind_envelope()  # the envelope's capacityAuthorizationDigest re-bound
        s.resign_envelope_and_record()  # envelope re-signed over ENVELOPE_DOMAIN_V2; record re-bound and re-signed
        self.assertReason("CAPACITY_SIGNATURE_INVALID", s.verify)

    def test_02_record_alone(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.record["signers"] = SINGLE  # not re-signed
        self.assertReason("LINUX_EVIDENCE_SIGNATURE_INVALID", s.verify)

    def test_03_all_three_every_digest_rebound_nothing_resigned(self):
        s = SignersSet.fresh(INDEPENDENT)
        for document in (s.envelope, s.capacity, s.record):
            document["signers"] = SINGLE
        s.bind_envelope()
        s.bind_record()
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_04_the_one_unrebound_tamper(self):
        # Capacity alone, nothing re-bound: LINUX_AUTHORITY_DIGEST_MISMATCH.
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE
        self.assertReason("LINUX_AUTHORITY_DIGEST_MISMATCH", s.verify)


# ===============================================================================================================
class Test06Replay(OracleCase):
    """Section 5 (b): replay across versions, each with the envelope's capacity digest re-bound."""

    def test_00_v1alpha1_pair_relabelled_v1alpha2_keeps_old_signatures(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.envelope = dict(deepcopy(s.v1.envelope), schemaVersion=ENVELOPE_SCHEMA_V2, signers=INDEPENDENT)
        s.capacity = dict(deepcopy(s.v1.capacity), schemaVersion=CAPACITY_SCHEMA_V2, signers=INDEPENDENT)
        s.bind_envelope()  # re-bound; the old v1alpha1 signatures are kept
        s.bind_record()
        s.sign_record()  # the v1alpha2 record kept valid over DOMAIN_V2
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_01_v1alpha2_pair_relabelled_v1alpha1_on_the_v1alpha1_path(self):
        s = SignersSet.fresh(INDEPENDENT)
        fixture = s.v1
        envelope, capacity = deepcopy(s.envelope), deepcopy(s.capacity)
        envelope["schemaVersion"], capacity["schemaVersion"] = ENVELOPE_SCHEMA_V1, CAPACITY_SCHEMA_V1
        del envelope["signers"], capacity["signers"]
        envelope["capacityAuthorizationDigest"] = byte_digest(canonical_bytes(capacity))  # re-bound, not re-signed
        fixture.envelope, fixture.capacity = envelope, capacity
        fixture.record["authority"] = fixture.bindings()
        fixture.resign_record()  # the v1alpha1 record kept valid over DOMAIN
        self.assertReason("PLATFORM_SIGNATURE_INVALID", verify_v1, fixture)

    def test_02_capacity_domain_replay(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signature"] = s.v1.capacity["signature"]  # the v1alpha1-signed capacity, re-labelled, signers added
        s.bind_envelope()
        s.resign_envelope_and_record()  # envelope re-bound and re-signed over ENVELOPE_DOMAIN_V2
        self.assertReason("CAPACITY_SIGNATURE_INVALID", s.verify)


# ===============================================================================================================
class Test07MixedDomains(OracleCase):
    """Section 5 (c): a mixed domain (SG3-5)."""

    def test_00_record_signed_over_the_v1alpha1_domain(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.sign_record(DOMAIN_V1)
        self.assertReason("LINUX_EVIDENCE_SIGNATURE_INVALID", s.verify)

    def test_01_envelope_signed_over_the_v1alpha1_domain(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.sign_envelope(ENVELOPE_DOMAIN_V1)
        s.bind_record()
        s.sign_record()
        self.assertReason("PLATFORM_SIGNATURE_INVALID", s.verify)

    def test_02_capacity_signed_over_the_v1alpha1_domain_isolates_the_capacity_domain(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.sign_capacity(CAPACITY_DOMAIN_V1)
        s.bind_envelope()
        s.resign_envelope_and_record()  # envelope re-bound and re-signed over ENVELOPE_DOMAIN_V2
        self.assertReason("CAPACITY_SIGNATURE_INVALID", s.verify)

    def test_03_tenant_signature_over_the_v1alpha1_domain(self):
        # Section 3 (verify_live_signatures_v2): the existing TENANT_SIGNATURE_INVALID code.
        s = SignersSet.fresh(INDEPENDENT)
        s.sign_envelope(ENVELOPE_DOMAIN_V1, roles=("tenant",))
        s.bind_record()
        s.sign_record()
        self.assertReason("TENANT_SIGNATURE_INVALID", s.verify)


# ===============================================================================================================
class Test08MixedVersions(OracleCase):
    """Section 5: mixed versions (restored from revision 1; SG2-2)."""

    def test_00_v2_record_with_a_v1alpha1_envelope(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.envelope = deepcopy(s.v1.envelope)
        s.bind_record()
        s.sign_record()
        self.assertReason("MISSING_FIELD", s.verify)

    def test_01_v2_record_with_a_v1alpha1_capacity(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity = deepcopy(s.v1.capacity)
        s.bind_envelope()
        s.resign_envelope_and_record()
        self.assertReason("MISSING_FIELD", s.verify)

    def test_02_v1alpha1_record_with_a_v2_envelope_and_capacity(self):
        s = SignersSet.fresh(INDEPENDENT)
        fixture = s.v1
        fixture.envelope, fixture.capacity = deepcopy(s.envelope), deepcopy(s.capacity)
        fixture.record["authority"] = fixture.bindings()
        fixture.resign_record()
        self.assertReason("UNKNOWN_FIELD", verify_v1, fixture)

    def test_03_v1alpha1_labelled_envelope_with_signers_on_the_v2_path(self):
        s = SignersSet.fresh(INDEPENDENT)
        s.envelope["schemaVersion"] = ENVELOPE_SCHEMA_V1
        s.resign_envelope_and_record()
        self.assertReason("UNSUPPORTED_ENVELOPE", s.verify)


# ===============================================================================================================
class Test09Isolation(OracleCase):
    """Section 5 (d) and section 3 (SG1-1): v1alpha2 never enters a shared path."""

    def documents(self):
        s = SignersSet.fresh(INDEPENDENT)
        bare_envelope = dict(deepcopy(s.envelope))
        del bare_envelope["signers"]
        bare_capacity = dict(deepcopy(s.capacity))
        del bare_capacity["signers"]
        return s, ((s.envelope, "UNKNOWN_FIELD"), (bare_envelope, "UNSUPPORTED_ENVELOPE")), (
            (s.capacity, "UNKNOWN_FIELD"), (bare_capacity, "UNSUPPORTED_CAPACITY"))

    def test_00_validate_envelope_and_validate_capacity(self):
        # live.py lines 115 and 157; the no-signers variants at lines 117 and 159.
        s, envelopes, capacities = self.documents()
        for envelope, reason in envelopes:
            with self.subTest(reason=reason):
                self.assertReason(reason, live.validate_envelope, envelope, now=INSTANT)
        for capacity, reason in capacities:
            with self.subTest(reason=reason):
                self.assertReason(reason, live.validate_capacity, capacity, s.v1.envelope, now=INSTANT)

    def test_01_unchanged_verify_linux_authority(self):
        s, envelopes, capacities = self.documents()
        trust = (canonical_bytes(s.release_trust), canonical_bytes(s.tenant_trust))
        for envelope, reason in envelopes:
            with self.subTest(document="envelope", reason=reason):
                self.assertReason(reason, live.verify_linux_authority, canonical_bytes(envelope),
                                  canonical_bytes(s.capacity), *trust, now=INSTANT)
        for capacity, reason in capacities:
            fixture = base_set()
            fixture.capacity = deepcopy(capacity)
            fixture.resign_authority()  # a v1alpha1 envelope re-bound to it and re-signed over the v1alpha1 domains
            with self.subTest(document="capacity", reason=reason):
                self.assertReason(reason, live.verify_linux_authority, canonical_bytes(fixture.envelope),
                                  canonical_bytes(fixture.capacity), canonical_bytes(fixture.release_trust),
                                  canonical_bytes(fixture.tenant_trust), now=INSTANT)

    def test_02_preflight(self):
        # live.py line 267 (reached from live_launcher.py line 91; the launcher's main needs installed custody, so the
        # nearest base-exposed call, preflight, is used).
        _, envelopes, _ = self.documents()
        for envelope, reason in envelopes:
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                (base / "envelope.json").write_bytes(canonical_bytes(envelope))
                with self.subTest(reason=reason):
                    self.assertReason(reason, live.preflight, base / "envelope.json", launcher_path=base / "launcher",
                                      release_trust_path=base / "release.json", tenant_trust_path=base / "tenant.json",
                                      now=INSTANT)

    def test_03_supervisor_envelope_check(self):
        # live_supervisor.py line 566, reached through NativeSupervisor.open_session as the base tests do
        # (tests/live_backend/test_supervisor.py lines 282-295); no reference may be read first.
        from harness_conformance import live_supervisor as supervisor
        _, envelopes, _ = self.documents()
        for envelope, reason in envelopes:
            shell = object.__new__(supervisor.NativeSupervisor)
            shell._mutex, shell._closed, shell._context = threading.Lock(), False, None
            with patch.object(supervisor, "utc_now", return_value=NOW), patch.object(
                    supervisor, "read_owned", side_effect=AssertionError("no reference may be read")) as reader:
                with self.subTest(reason=reason):
                    self.assertReason(reason, shell.open_session, canonical_bytes(envelope))
            self.assertEqual(reader.call_count, 0)

    def test_04_backend_authority(self):
        # live_backend_authority.py line 50.
        from harness_conformance.live_backend_authority import verify_backend_authority
        s, envelopes, _ = self.documents()
        for envelope, reason in envelopes:
            with self.subTest(reason=reason):
                self.assertReason(reason, verify_backend_authority, canonical_bytes(envelope),
                                  canonical_bytes(s.capacity), canonical_bytes(s.release_trust),
                                  canonical_bytes(s.tenant_trust), now=INSTANT)


# ===============================================================================================================
class Test10PacketScope(OracleCase):
    """Section 5 (f) (MON-SG-PKTID): packetId CONF-LINUX-001 and PACKET_DIGEST on the v1alpha2 path."""

    def test_00_other_packet_id_or_digest(self):
        for field, value in (("packetId", "CONF-LINUX-002"), ("packetDigest", OTHER_DIGEST)):
            s = SignersSet.fresh(INDEPENDENT)
            s.envelope[field] = value
            s.resign_envelope_and_record()
            with self.subTest(field=field):
                self.assertReason("LINUX_ENVELOPE_SCOPE_MISMATCH", s.verify)

    def test_01_v2_envelope_keeps_the_conf_linux_001_scope(self):
        s = SignersSet.fresh(INDEPENDENT)
        self.assertEqual(s.envelope["packetId"], "CONF-LINUX-001")
        self.assertEqual(s.envelope["packetDigest"], lr.PACKET_DIGEST)
        self.assertEqual(lr.PACKET_DIGEST, "sha256:22f00544680f90a90b03420632bebf192a8c687549b519770fca5f98dd5fd6c9")
        self.assertEqual(s.verify(), expected_result(s.record))


# ===============================================================================================================
class Test11OtherFindings(OracleCase):
    """Section 5 (h)."""

    def test_00_schema_validate_refuses_a_v2_record(self):
        s = SignersSet.fresh(INDEPENDENT)
        self.assertReason("UNKNOWN_FIELD", schema_module.validate, "linux-readiness-evidence", s.record)

    def test_01_cli_validate_refuses_a_v2_record(self):
        from harness_conformance import cli
        s = SignersSet.fresh(INDEPENDENT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_bytes(canonical_bytes(s.record))
            errors, output = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                code = cli.main(["validate", "--kind", "linux-readiness-evidence", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(errors.getvalue()), {"reasonCode": "UNKNOWN_FIELD", "status": "FAIL"})
        self.assertEqual(output.getvalue(), "")

    def test_02_non_object_record_keeps_type_mismatch(self):
        # SG2-2: today's code.
        s = SignersSet.fresh(INDEPENDENT)
        for value in ([], "record", 7):
            with self.subTest(value=value):
                self.assertReason("TYPE_MISMATCH", lr.verify_linux_evidence, canonical_bytes(value), **s.inputs())

    def test_03_unknown_version_without_signers(self):
        # SG1-4, SG2-2: LINUX_EVIDENCE_SCHEMA_INVALID (linux_readiness.py line 161).
        s = SignersSet.fresh(INDEPENDENT)
        del s.record["signers"]
        s.record["schemaVersion"] = "harness.planeon.ai/linux-readiness-evidence/v1alpha3"
        s.sign_record(DOMAIN_V1)
        self.assertReason("LINUX_EVIDENCE_SCHEMA_INVALID", s.verify)

    def test_04_v1alpha1_record_carrying_signers(self):
        fixture = base_set()
        fixture.record["signers"] = INDEPENDENT
        fixture.resign_record()
        self.assertReason("UNKNOWN_FIELD", verify_v1, fixture)

    def test_05_malformed_input_inside_verify_linux_authority_v2(self):
        # SG2-3, SG3-3: permittedEndpointIds holding a list raises TypeError at live.py line 176, inside
        # validate_capacity on the copy, inside the try: LINUX_AUTHORITY_MALFORMED.
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["permittedEndpointIds"] = [["unit-proxy"]]
        s.resign_all()
        self.assertReason("LINUX_AUTHORITY_MALFORMED", s.authority)
        self.assertReason("LINUX_AUTHORITY_MALFORMED", s.verify)


# ===============================================================================================================
class Test12Sg12Table(OracleCase):
    """Section 10: SG1-2's three steps, one vector each; and the step order of section 3's v2 validators."""

    def test_00_closed_original_check(self):
        # signers missing from a v1alpha2 document: MISSING_FIELD.
        s = SignersSet.fresh(INDEPENDENT)
        del s.envelope["signers"]
        s.resign_envelope_and_record()
        self.assertReason("MISSING_FIELD", s.verify)
        self.assertReason("MISSING_FIELD", live.validate_envelope_v2, s.envelope, now=INSTANT)

    def test_01_copy_validated_for_refusals_only(self):
        # equal platform and tenant key ids in a v1alpha2 envelope: SIGNER_ROLES_NOT_INDEPENDENT (line 149, raised
        # inside validate_envelope on the copy).
        s = SignersSet.fresh(INDEPENDENT)
        s.envelope["tenantSignerKeyId"] = s.envelope["platformSignerKeyId"]
        s.resign_envelope_and_record()
        self.assertReason("SIGNER_ROLES_NOT_INDEPENDENT", s.verify)
        self.assertReason("SIGNER_ROLES_NOT_INDEPENDENT", live.validate_envelope_v2, s.envelope, now=INSTANT)

    def test_02_every_payload_over_the_original_with_the_v2_domains(self):
        # (a)'s capacity tamper, re-bound, with the envelope re-signed: CAPACITY_SIGNATURE_INVALID.
        s = SignersSet.fresh(INDEPENDENT)
        s.capacity["signers"] = SINGLE
        s.bind_envelope()
        s.resign_envelope_and_record()
        self.assertReason("CAPACITY_SIGNATURE_INVALID", s.verify)
        self.assertReason("CAPACITY_SIGNATURE_INVALID", live.verify_live_signatures_v2, s.envelope, s.capacity,
                          s.release_trust, s.tenant_trust, now=INSTANT)

    def test_03_envelope_validator_step_order(self):
        # Section 3, validate_envelope_v2: object, closed original, version, signers, then the copy.
        s = SignersSet.fresh(INDEPENDENT)
        self.assertReason("TYPE_MISMATCH", live.validate_envelope_v2, [], now=INSTANT)
        missing = deepcopy(s.envelope)
        del missing["signers"]
        missing["schemaVersion"] = ENVELOPE_SCHEMA_V1
        self.assertReason("MISSING_FIELD", live.validate_envelope_v2, missing, now=INSTANT)
        self.assertReason("UNKNOWN_FIELD", live.validate_envelope_v2, dict(s.envelope, extra="x"), now=INSTANT)
        wrong = dict(s.envelope, schemaVersion=ENVELOPE_SCHEMA_V1, signers=UNKNOWN_SIGNERS)
        self.assertReason("UNSUPPORTED_ENVELOPE", live.validate_envelope_v2, wrong, now=INSTANT)
        self.assertReason("LINUX_SIGNERS_INVALID", live.validate_envelope_v2,
                          dict(s.envelope, signers=UNKNOWN_SIGNERS, mutationProfile="ALLOW_ALL"), now=INSTANT)
        self.assertReason("MUTATION_PROFILE_FORBIDDEN", live.validate_envelope_v2,
                          dict(s.envelope, mutationProfile="ALLOW_ALL"), now=INSTANT)

    def test_04_capacity_validator_step_order(self):
        # Section 3, validate_capacity_v2: the same pattern and order.
        s = SignersSet.fresh(INDEPENDENT)
        self.assertReason("TYPE_MISMATCH", live.validate_capacity_v2, [], s.envelope, now=INSTANT)
        missing = deepcopy(s.capacity)
        del missing["signers"]
        missing["schemaVersion"] = CAPACITY_SCHEMA_V1
        self.assertReason("MISSING_FIELD", live.validate_capacity_v2, missing, s.envelope, now=INSTANT)
        self.assertReason("UNKNOWN_FIELD", live.validate_capacity_v2, dict(s.capacity, extra="x"), s.envelope,
                          now=INSTANT)
        wrong = dict(s.capacity, schemaVersion=CAPACITY_SCHEMA_V1, signers=UNKNOWN_SIGNERS)
        self.assertReason("UNSUPPORTED_CAPACITY", live.validate_capacity_v2, wrong, s.envelope, now=INSTANT)
        self.assertReason("LINUX_SIGNERS_INVALID", live.validate_capacity_v2,
                          dict(s.capacity, signers=UNKNOWN_SIGNERS, tenantId="other-tenant"), s.envelope, now=INSTANT)
        self.assertReason("CAPACITY_BINDING_MISMATCH", live.validate_capacity_v2,
                          dict(s.capacity, tenantId="other-tenant"), s.envelope, now=INSTANT)

    def test_05_record_validator_step_order(self):
        # Section 3, _validate_linux_evidence_v2: object, closed original, version, signers, then the copy.
        s = SignersSet.fresh(INDEPENDENT)
        self.assertReason("TYPE_MISMATCH", lr._validate_linux_evidence_v2, [])
        missing = deepcopy(s.record)
        del missing["signers"]
        missing["schemaVersion"] = SCHEMA_V1
        self.assertReason("MISSING_FIELD", lr._validate_linux_evidence_v2, missing)
        self.assertReason("UNKNOWN_FIELD", lr._validate_linux_evidence_v2, dict(s.record, extra="x"))
        wrong = dict(s.record, schemaVersion=SCHEMA_V1, signers=UNKNOWN_SIGNERS)
        self.assertReason("LINUX_EVIDENCE_SCHEMA_INVALID", lr._validate_linux_evidence_v2, wrong)
        bad_case = deepcopy(s.record)
        bad_case["cases"][0]["status"] = "WARN"
        self.assertReason("LINUX_SIGNERS_INVALID", lr._validate_linux_evidence_v2,
                          dict(bad_case, signers=UNKNOWN_SIGNERS))
        self.assertReason("LINUX_CASE_INVENTORY_INVALID", lr._validate_linux_evidence_v2, bad_case)

    def test_06_v2_validators_return_the_originals(self):
        # Section 3: each v2 validator returns the original v1alpha2 document.
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            with self.subTest(signers=signers):
                envelope = live.validate_envelope_v2(deepcopy(s.envelope), now=INSTANT)
                self.assertEqual(envelope, s.envelope)
                self.assertEqual((envelope["schemaVersion"], envelope["signers"]), (ENVELOPE_SCHEMA_V2, signers))
                capacity = live.validate_capacity_v2(deepcopy(s.capacity), deepcopy(s.envelope), now=INSTANT)
                self.assertEqual(capacity, s.capacity)
                self.assertEqual((capacity["schemaVersion"], capacity["signers"]), (CAPACITY_SCHEMA_V2, signers))
                record = lr._validate_linux_evidence_v2(deepcopy(s.record))
                self.assertEqual(record, s.record)
                self.assertEqual((record["schemaVersion"], record["signers"]), (SCHEMA_V2, signers))
                live.verify_live_signatures_v2(s.envelope, s.capacity, s.release_trust, s.tenant_trust, now=INSTANT)


# ===============================================================================================================
class Test13Positives(OracleCase):
    """Section 5: the positives."""

    def test_00_v2_set_passes_end_to_end_under_each_value(self):
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            owners = [s.key(role)["owner"] for role in ROLES]
            if signers == SINGLE:
                self.assertEqual(owners, [SINGLE_PRINCIPAL_OWNER] * 3)
                self.assertEqual(len({s.key(role)["publicKey"] for role in ROLES}), 3)
            else:
                self.assertEqual(len(set(owners)), 3)
                self.assertNotIn(SINGLE_PRINCIPAL_OWNER, owners)
            with self.subTest(signers=signers):
                self.assertEqual(s.verify(), expected_result(s.record))

    def test_01_verify_linux_authority_v2_returns_the_originals_and_the_agreed_value(self):
        # Section 3: it returns the original envelope and capacity, the two trust bundles, and the agreed signers.
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            with self.subTest(signers=signers):
                result = s.authority()
                self.assertEqual(len(result), 5)
                envelope, capacity, release_trust, tenant_trust, agreed = result
                self.assertEqual(envelope, s.envelope)
                self.assertEqual(capacity, s.capacity)
                self.assertEqual(release_trust, s.release_trust)
                self.assertEqual(tenant_trust, s.tenant_trust)
                self.assertEqual(agreed, signers)

    def test_02_v1alpha1_set_passes_through_the_unchanged_path(self):
        fixture = base_set()
        self.assertEqual(verify_v1(fixture), expected_result(fixture.record))
        envelope, capacity, release_trust, tenant_trust = live.verify_linux_authority(
            canonical_bytes(fixture.envelope), canonical_bytes(fixture.capacity), canonical_bytes(fixture.release_trust),
            canonical_bytes(fixture.tenant_trust), now=INSTANT)
        self.assertEqual((envelope, capacity), (fixture.envelope, fixture.capacity))

    def test_03_oracle_builder_self_check(self):
        # The oracle's own signer: originals signed over the v2 domains, digests bound (section 5's fixture rule).
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            keys = {role: public_key(s.seeds[role]) for role in ROLES}
            envelope_payload = signature_payload(ENVELOPE_DOMAIN_V2, s.envelope, ("platformSignature", "tenantSignature"))
            for role in ("platform", "tenant"):
                self.assertTrue(verify(keys[role], envelope_payload, _decode(s.envelope[role + "Signature"])))
            self.assertTrue(verify(keys["capacity"], signature_payload(CAPACITY_DOMAIN_V2, s.capacity, ("signature",)),
                                   _decode(s.capacity["signature"])))
            record_payload = signature_payload(DOMAIN_V2, s.record, RECORD_SIGNATURES)
            for role in ROLES:
                self.assertTrue(verify(keys[role], record_payload, _decode(s.record[role + "Signature"])))
            self.assertEqual(s.envelope["capacityAuthorizationDigest"], byte_digest(canonical_bytes(s.capacity)))
            self.assertEqual(s.record["authority"]["envelopeDigest"], byte_digest(canonical_bytes(s.envelope)))
            self.assertEqual(s.record["authority"]["capacityDigest"], byte_digest(canonical_bytes(s.capacity)))
            unsigned = {"capacityAuthorizationDigest", "releaseTrustStoreDigest", "tenantTrustStoreDigest",
                        "platformSignature", "tenantSignature"}
            for v2, v1, version in ((s.envelope, s.v1.envelope, ENVELOPE_SCHEMA_V1),
                                    (s.capacity, s.v1.capacity, CAPACITY_SCHEMA_V1)):
                relabelled = {key: value for key, value in v2.items() if key not in unsigned | {"signers", "signature"}}
                relabelled["schemaVersion"] = version
                self.assertEqual(relabelled, {key: value for key, value in v1.items()
                                              if key not in unsigned | {"signature"}})


# ===============================================================================================================
class Test14SchemaRuntimeAgree(OracleCase):
    """Section 5 (e) and section 4: schema and runtime agree (SG2-4, SG3-4)."""

    def test_00_section_4_exact_differences_from_v1alpha1(self):
        for kind, version in (("envelope", ENVELOPE_SCHEMA_V2), ("capacity", CAPACITY_SCHEMA_V2),
                              ("evidence", SCHEMA_V2)):
            v1, v2 = load_schema("v1alpha1", kind), load_schema("v1alpha2", kind)
            with self.subTest(kind=kind):
                self.assertEqual(v1["$id"].count("/v1alpha1/"), 1)
                self.assertEqual(v2["$id"], v1["$id"].replace("/v1alpha1/", "/v1alpha2/"))
                self.assertEqual(v2["properties"]["schemaVersion"], {"const": version})
                self.assertEqual(v2["required"].count("signers"), 1)
                self.assertEqual(v2["properties"].get("signers"), SIGNERS_PROPERTY)
                self.assertIs(v2.get("additionalProperties"), False)
                actual = deepcopy(v2)
                actual["required"].remove("signers")
                del actual["properties"]["signers"]
                expected = deepcopy(v1)
                expected["$id"] = v2["$id"]
                expected["properties"]["schemaVersion"] = {"const": version}
                self.assertEqual(actual, expected)
        evidence = load_schema("v1alpha2", "evidence")
        # Section 4: the nested plan const stays v1alpha1.
        self.assertEqual(evidence["$defs"]["plan"]["properties"]["schemaVersion"], {"const": PLAN_SCHEMA_V1})

    def test_01_every_ref_resolves_22_and_3(self):
        counts = {}
        for kind in SCHEMA_FILES:
            document = load_schema("v1alpha2", kind)
            counts[kind] = reference_uses(document, document)
        self.assertEqual(counts["envelope"], 22)
        self.assertEqual(counts["capacity"], 3)
        v1_evidence = load_schema("v1alpha1", "evidence")
        self.assertEqual(counts["evidence"], reference_uses(v1_evidence, v1_evidence))

    def test_02_v2_documents_pass_the_v2_schemas(self):
        for signers in SIGNERS:
            s = SignersSet.fresh(signers)
            for kind, document in (("envelope", s.envelope), ("capacity", s.capacity), ("evidence", s.record)):
                schema = load_schema("v1alpha2", kind)
                with self.subTest(signers=signers, kind=kind):
                    schema_assert(document, schema, schema)

    def test_03_signers_missing_or_unknown_fails_schema_and_runtime(self):
        s = SignersSet.fresh(INDEPENDENT)
        runtime = {
            "envelope": lambda document: live.validate_envelope_v2(document, now=INSTANT),
            "capacity": lambda document: live.validate_capacity_v2(document, s.envelope, now=INSTANT),
            "evidence": lr._validate_linux_evidence_v2,
        }
        for kind, document in (("envelope", s.envelope), ("capacity", s.capacity), ("evidence", s.record)):
            schema = load_schema("v1alpha2", kind)
            missing = deepcopy(document)
            del missing["signers"]
            unknown = dict(deepcopy(document), signers=UNKNOWN_SIGNERS)
            for label, changed, reason in (("missing", missing, "MISSING_FIELD"),
                                           ("unknown", unknown, "LINUX_SIGNERS_INVALID")):
                with self.subTest(kind=kind, signers=label):
                    with self.assertRaises(AssertionError):
                        schema_assert(changed, schema, schema)
                    self.assertReason(reason, runtime[kind], changed)

    def test_04_v1alpha1_documents_fail_the_v2_schemas(self):
        fixture = base_set()
        for kind, document in (("envelope", fixture.envelope), ("capacity", fixture.capacity),
                               ("evidence", fixture.record)):
            schema = load_schema("v1alpha2", kind)
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                schema_assert(document, schema, schema)

    def test_05_interpreter_sanity_on_the_v1alpha1_schemas(self):
        # The local interpreter accepts the unchanged v1alpha1 fixture under the v1alpha1 schemas (the unchanged path).
        fixture = base_set()
        for kind, document in (("envelope", fixture.envelope), ("capacity", fixture.capacity),
                               ("evidence", fixture.record)):
            schema = load_schema("v1alpha1", kind)
            with self.subTest(kind=kind):
                schema_assert(document, schema, schema)
        envelope = load_schema("v1alpha1", "envelope")
        capacity = load_schema("v1alpha1", "capacity")
        self.assertEqual(reference_uses(envelope, envelope), 22)
        self.assertEqual(reference_uses(capacity, capacity), 3)

    def test_06_interpreter_refuses_bad_refs_and_duplicate_items(self):
        root = {"$defs": {"digest": {"type": "string"}}}
        for reference in ("#/$defs/missing", "https://schemas.example.invalid/other.json", "#/properties/x",
                          "#/$defs/digest/type", 7):
            with self.subTest(reference=reference), self.assertRaises(SchemaReferenceError):
                schema_assert("x", {"$ref": reference}, root)
        with self.assertRaises(SchemaReferenceError):
            reference_uses({"properties": {"a": {"$ref": "#/$defs/missing"}}}, root)
        with self.assertRaises(AssertionError):
            schema_assert(["a", "a"], {"type": "array", "uniqueItems": True}, root)
        schema_assert(["a", "b"], {"type": "array", "uniqueItems": True}, root)
        with self.assertRaises(AssertionError):
            schema_assert(7, {"$ref": "#/$defs/digest"}, root)


# ===============================================================================================================
class Test15CodeRules(OracleCase):
    """Section 3's code rules, at run time by ast on the subject's source files."""

    def test_00_no_new_top_level_import_in_linux_readiness(self):
        # SG1-5.
        tree = ast.parse(source_text("src/harness_conformance/linux_readiness.py"))
        self.assertEqual(top_level_imports(tree), BASE_LR_TOP_IMPORTS)

    def test_01_linux_readiness_ast_rules(self):
        # test_linux_inventory.py lines 76-86: no os, pathlib, subprocess or socket import; no open, exec or eval.
        tree = ast.parse(source_text("src/harness_conformance/linux_readiness.py"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse({alias.name.split(".")[0] for alias in node.names} & LR_FORBIDDEN_MODULES)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], LR_FORBIDDEN_MODULES)
                self.assertNotIn("sign", {alias.name for alias in node.names})
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, FORBIDDEN_CALLS)

    def test_02_live_has_no_open_exec_or_eval_call(self):
        tree = ast.parse(source_text("src/harness_conformance/live.py"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, FORBIDDEN_CALLS)

    def test_03_source_tokens_and_stdlib_only(self):
        # SG1-10: no enforcement/ bytes (test_bootstrap.py line 283) and no zero-bill source token (ci/zero_bill.py
        # lines 12-15); stdlib-only (test_bootstrap.py lines 276-284).
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        for relative in ("src/harness_conformance/live.py", "src/harness_conformance/linux_readiness.py"):
            raw = (ROOT / relative).read_bytes()
            with self.subTest(path=relative):
                self.assertNotIn(b"enforcement/", raw)
                self.assertNotIn(b"tests.enforcement", raw)
                self.assertNotIn(b"enforcement_tests", raw)
                text = raw.decode("utf-8")
                for token in ZERO_BILL_SOURCE_FORBIDDEN:
                    self.assertNotIn(token, text)
                self.assertLessEqual(absolute_import_tops(ast.parse(raw)), allowed)

    def test_04_every_base_line_of_live_is_present_in_order(self):
        # Section 3: live.py additions only, no existing line changes.
        self.assertEqual(len(BASE_LIVE_LINE_DIGESTS), 344)
        lines = source_text("src/harness_conformance/live.py").split("\n")
        actual = [hashlib.sha256(line.encode()).hexdigest()[:16] for line in lines]
        self.assertTrue(is_subsequence(BASE_LIVE_LINE_DIGESTS, actual))

    def test_05_shared_validators_are_byte_for_byte(self):
        # Section 3 (MON-SG-2 (a), MON-SG-4, Q-SG-6, SG1-3 (a)): the shared validators stay exactly as they are.
        live_text = source_text("src/harness_conformance/live.py")
        for name, digest in BASE_LIVE_NODES.items():
            with self.subTest(module="live", name=name):
                self.assertEqual(node_digest(live_text, name), digest)
        lr_text = source_text("src/harness_conformance/linux_readiness.py")
        self.assertEqual(node_digest(lr_text, "validate_linux_evidence"), BASE_LR_NODES["validate_linux_evidence"])

    def test_06_shared_names_keep_name_value_and_behaviour(self):
        # Section 3 (SG1-9) and "linux_readiness.py additions": every base top-level name other than
        # verify_linux_evidence (which holds the dispatch) keeps its exact source.
        lr_text = source_text("src/harness_conformance/linux_readiness.py")
        for name, digest in BASE_LR_NODES.items():
            with self.subTest(name=name):
                self.assertEqual(node_digest(lr_text, name), digest)

    def test_07_src_changes_only_the_two_modules(self):
        # Q-SG-6 (design-status gateMaterial): src/ changes only live.py and linux_readiness.py; no new module.
        files = {path.relative_to(ROOT / "src/harness_conformance").as_posix()
                 for path in (ROOT / "src").rglob("*.py")}
        self.assertEqual(files, BASE_SRC_FILES)


# ===============================================================================================================
class Test16UnchangedBaseFiles(OracleCase):
    """Sections 4-6: files that stay byte-identical to the base."""

    def test_00_base_fixture_and_v1alpha1_schemas_and_boundary_doc(self):
        for relative, digest in BASE_SHA256.items():
            with self.subTest(path=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
