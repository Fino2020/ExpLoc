"""
CWE Archetype definitions — mechanism families with ordered slots.

Each archetype captures the causal chain of a vulnerability mechanism:
stages (slots) that source data, perform operations, and reach impact.

Slots marked REQUIRED must be filled for a complete explanation.
Slots marked OPTIONAL may be filled if the trace naturally passes through them.

All definitions derived from 1000.csv CWE descriptions and hierarchy.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Slot:
    """One stage in a vulnerability mechanism chain."""
    name: str                       # "Source", "MissingBoundsCheck", etc.
    description: str                # Semantic definition for LLM classification
    required: bool = True           # REQUIRED vs OPTIONAL
    order: int = 0                  # Expected position in causal chain (0-based)

    def to_prompt_line(self) -> str:
        tag = "[REQUIRED]" if self.required else "[OPTIONAL]"
        return f"{tag} {self.name}: {self.description}"


@dataclass
class Archetype:
    """CWE family archetype — ordered sequence of mechanism stages."""
    family: str                     # "Memory-Buffer-Overflow"
    display_name: str               # Human-readable name
    slots: List[Slot]               # Ordered mechanism stages
    cwe_types: List[str]            # CWE-IDs covered (without "CWE-" prefix)
    edge_weight_profile: Dict[str, float] = field(default_factory=dict)

    @property
    def required_slots(self) -> List[Slot]:
        return [s for s in self.slots if s.required]

    @property
    def optional_slots(self) -> List[Slot]:
        return [s for s in self.slots if not s.required]

    @property
    def slot_names(self) -> List[str]:
        return [s.name for s in self.slots]

    @property
    def required_slot_names(self) -> Set[str]:
        return {s.name for s in self.slots if s.required}

    def get_slot_by_name(self, name: str) -> Optional[Slot]:
        for s in self.slots:
            if s.name == name:
                return s
        return None

    def get_slot_prompt(self) -> str:
        """Build prompt section listing all slots with descriptions."""
        lines = [f"Vulnerability Family: {self.display_name}"]
        for s in self.slots:
            lines.append(s.to_prompt_line())
        return "\n".join(lines)


# ============================================================================
# Default edge weight profiles per family
# Weights learned conceptually from CWE mechanism patterns.
# In production, these would be estimated from training data (other CVEs).
# ============================================================================

_DEFAULT_EDGE_WEIGHTS = {
    "data_flow": 2.0,
    "call": 1.5,
    "cfg": 0.5,
    "inter_call": 0.8,
    "return": 0.3,
}


def _mem_profile(**overrides) -> Dict[str, float]:
    p = {**_DEFAULT_EDGE_WEIGHTS,
         "data_flow": 3.0,
         "call_to_mem": 5.0,    # memcpy, malloc, free, etc.
         "call_to_str": 4.0,     # strcpy, strlen, etc.
         "call_to_log": 0.2,
         **overrides}
    return p


def _injection_profile(**overrides) -> Dict[str, float]:
    p = {**_DEFAULT_EDGE_WEIGHTS,
         "data_flow": 4.0,
         "call_to_exec": 5.0,    # system, exec, eval, etc.
         "call_to_query": 5.0,   # mysql_query, etc.
         "call_to_log": 0.2,
         **overrides}
    return p


def _auth_profile(**overrides) -> Dict[str, float]:
    p = {**_DEFAULT_EDGE_WEIGHTS,
         "cfg": 0.3,
         "branch": 1.0,
         "call_to_auth_check": 5.0,
         "call_to_admin": 3.0,
         **overrides}
    return p


def _web_profile(**overrides) -> Dict[str, float]:
    """Web-specific: emphasize request handling, URL ops, redirect, fetch."""
    p = {**_DEFAULT_EDGE_WEIGHTS,
         "data_flow": 2.5,
         "call": 2.0,
         "call_to_exec": 4.0,
         "call_to_query": 3.0,
         "call_to_web": 4.0,      # HTTP handlers, redirect, fetch, request parsing
         "cfg": 0.15,
         **overrides}
    return p


# ============================================================================
# Full Archetype Library — ~15 families covering all 81 dataset CWEs
# ============================================================================

ARCHETYPE_LIBRARY: List[Archetype] = [
    # ------------------------------------------------------------------
    # Memory Safety — Buffer Overflow / Out-of-Bounds Access
    # Covers: 787, 125, 119, 120, 121, 122, 123, 124, 126, 127, 129, 130, 131, 466, 786, 788, 823, 824, 825
    # Hierarchy: CWE-118 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Buffer-Overflow",
        display_name="Buffer Overflow / Out-of-Bounds Memory Access",
        slots=[
            Slot("Source", "Untrusted input acquisition — reads data from user, network, file, or IPC", True, 0),
            Slot("BufferAllocation", "Memory buffer allocation — stack or heap buffer created with fixed capacity", False, 1),
            Slot("SizeComputation", "Input size or length computation — strlen, sizeof, or arithmetic on input dimensions", False, 2),
            Slot("MissingBoundsCheck", "Absence or bypass of bounds verification before memory write/read", True, 3),
            Slot("OutOfBoundsAccess", "Memory read or write beyond allocated buffer boundary", True, 4),
            Slot("Corruption", "Memory corruption, crash, code execution, or information disclosure", True, 5),
        ],
        cwe_types=["787", "125", "119", "120", "121", "122", "123", "124", "126", "127",
                    "129", "130", "131", "466", "786", "788", "823", "824", "825", "843"],
        edge_weight_profile=_mem_profile(call_to_mem=5.0, call_to_str=4.0),
    ),

    # ------------------------------------------------------------------
    # Memory Safety — Use After Free
    # Covers: 416
    # Hierarchy: CWE-825 → CWE-119 → CWE-118 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Use-After-Free",
        display_name="Use After Free",
        slots=[
            Slot("Allocation", "Memory allocation — malloc/new creating an object on the heap", True, 0),
            Slot("Free", "Memory deallocation — free/delete releasing the object", True, 1),
            Slot("DanglingReference", "Dangling pointer retained — reference to freed memory persists in program state", False, 2),
            Slot("UseAfterFree", "Access through dangling pointer — read/write/call on freed memory", True, 3),
            Slot("Corruption", "Memory corruption, crash, or arbitrary code execution", True, 4),
        ],
        cwe_types=["416"],
        edge_weight_profile=_mem_profile(call_to_mem=5.0),
    ),

    # ------------------------------------------------------------------
    # Memory Safety — Double Free
    # Covers: 415
    # Hierarchy: CWE-825 → CWE-119 → CWE-118 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Double-Free",
        display_name="Double Free",
        slots=[
            Slot("Allocation", "Memory allocation — malloc/new creating an object", True, 0),
            Slot("FirstFree", "First deallocation — free/delete called on the pointer", True, 1),
            Slot("MissingNullify", "Pointer not set to NULL after free — reference still valid in program state", True, 2),
            Slot("SecondFree", "Second deallocation — free/delete called again on same pointer", True, 3),
            Slot("Corruption", "Heap corruption, crash, or arbitrary code execution", True, 4),
        ],
        cwe_types=["415"],
        edge_weight_profile=_mem_profile(call_to_mem=5.0),
    ),

    # ------------------------------------------------------------------
    # Memory Safety — NULL Pointer Dereference
    # Covers: 476, 690
    # Hierarchy: CWE-710
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Null-Dereference",
        display_name="NULL Pointer Dereference",
        slots=[
            Slot("PointerAcquisition", "Pointer/object acquisition — function return, allocation, or parameter", True, 0),
            Slot("MissingNullCheck", "Missing NULL check — path where null guard is absent or bypassed", True, 1),
            Slot("Dereference", "Pointer dereference — member access, array index, or function call through pointer", True, 2),
            Slot("Crash", "Null dereference crash — segmentation fault, exception, or abnormal termination", True, 3),
        ],
        cwe_types=["476", "690"],
        edge_weight_profile=_mem_profile(call_to_mem=2.0),
    ),

    # ------------------------------------------------------------------
    # Memory Safety — Uninitialized Resource
    # Covers: 908, 909, 456, 457, 665, 824
    # Hierarchy: CWE-665 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Uninitialized-Use",
        display_name="Use of Uninitialized Resource",
        slots=[
            Slot("Declaration", "Resource declaration — variable, buffer, or pointer declared without initial value", True, 0),
            Slot("MissingInitialization", "Missing initialization — path where init is skipped or conditional", True, 1),
            Slot("UninitializedUse", "Use of uninitialized value — read, branch, or pass to operation", True, 2),
            Slot("UndefinedBehavior", "Undefined behavior — crash, wrong computation, or information leak", True, 3),
        ],
        cwe_types=["908", "909", "456", "457", "665", "824"],
        edge_weight_profile=_mem_profile(),
    ),

    # ------------------------------------------------------------------
    # Memory Safety — Memory/Resource Leak
    # Covers: 401, 772, 775, 404, 459
    # Hierarchy: CWE-404 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Memory-Leak",
        display_name="Memory / Resource Leak",
        slots=[
            Slot("Allocation", "Resource allocation — memory, file handle, socket, or other limited resource acquired", True, 0),
            Slot("MissingRelease", "Missing release — allocation not freed/closed on all execution paths", True, 1),
            Slot("Accumulation", "Resource accumulation — repeated allocations without corresponding releases", False, 2),
            Slot("Exhaustion", "Resource exhaustion — out of memory, file descriptors, or handles → denial of service", True, 3),
        ],
        cwe_types=["401", "772", "775", "404", "459", "672"],
        edge_weight_profile=_mem_profile(call_to_mem=3.0),
    ),

    # ------------------------------------------------------------------
    # Integer Errors
    # Covers: 190, 191, 193, 369, 680, 681, 682, 839, 131, 134, 128
    # Hierarchy: CWE-682
    # ------------------------------------------------------------------
    Archetype(
        family="Integer-Error",
        display_name="Integer Overflow / Wraparound / Numeric Error",
        slots=[
            Slot("Source", "Numeric input acquisition — user-supplied number, size, count, or index", True, 0),
            Slot("ArithmeticOperation", "Arithmetic operation — addition, multiplication, subtraction with external input", True, 1),
            Slot("MissingBoundsCheck", "Missing bounds verification — no check for overflow/wraparound/underflow before operation", True, 2),
            Slot("OverflowValue", "Incorrect numeric result — wrapped, truncated, or overflowed value produced", True, 3),
            Slot("CorruptUse", "Corrupt downstream use — wrong allocation size, index out of bounds, or logic error", True, 4),
        ],
        cwe_types=["190", "191", "193", "369", "680", "681", "682", "839", "131", "134", "128",
                    "189", "789", "1284"],
        edge_weight_profile=_mem_profile(call_to_mem=2.0),
    ),

    # ------------------------------------------------------------------
    # Injection — OS Command
    # Covers: 78, 77
    # Hierarchy: CWE-77 → CWE-74 → CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-OS-Command",
        display_name="OS Command Injection",
        slots=[
            Slot("Source", "Untrusted input acquisition — user-controlled data from HTTP, file, or network", True, 0),
            Slot("BuildCommand", "Command string construction — concatenating input into system command", True, 1),
            Slot("MissingSanitization", "Missing input sanitization — special shell characters not escaped or filtered", True, 2),
            Slot("Execute", "Command execution — system(), popen(), exec() called with attacker-controlled string", True, 3),
            Slot("Impact", "Arbitrary command execution — attacker runs commands with application privileges", True, 4),
        ],
        cwe_types=["78", "77"],
        edge_weight_profile=_injection_profile(call_to_exec=5.0),
    ),

    # ------------------------------------------------------------------
    # Injection — SQL Injection
    # Covers: 89, 90, 91, 564
    # Hierarchy: CWE-74 → CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-SQL",
        display_name="SQL Injection",
        slots=[
            Slot("Source", "Untrusted input acquisition — user-controlled data from HTTP request or form", True, 0),
            Slot("BuildQuery", "SQL string construction — concatenating input into SQL query string", True, 1),
            Slot("NoParameterization", "Missing parameterized query — string concatenation instead of prepared statement", True, 2),
            Slot("Execute", "Query execution — SQL query sent to database with injected logic", True, 3),
            Slot("Impact", "Data breach, modification, or privilege escalation", True, 4),
        ],
        cwe_types=["89", "90", "91", "564"],
        edge_weight_profile=_injection_profile(call_to_query=5.0, call_to_exec=4.0),
    ),

    # ------------------------------------------------------------------
    # Injection — Code Injection
    # Covers: 94, 95, 96, 98
    # Hierarchy: CWE-74 → CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-Code",
        display_name="Code Injection",
        slots=[
            Slot("Source", "Untrusted input acquisition — user-controlled data entering the application", True, 0),
            Slot("BuildCode", "Code string construction — concatenating input into eval/exec/require argument", True, 1),
            Slot("MissingSanitization", "Missing input sanitization — no filtering of code syntax elements", True, 2),
            Slot("Execute", "Code execution — eval(), exec(), include() with attacker-controlled string", True, 3),
            Slot("Impact", "Arbitrary code execution — attacker code runs in application context", True, 4),
        ],
        cwe_types=["94", "95", "96", "98"],
        edge_weight_profile=_injection_profile(call_to_exec=5.0),
    ),

    # ------------------------------------------------------------------
    # Injection — Cross-Site Scripting (XSS)
    # Covers: 79, 80, 81, 82, 83, 84, 85, 86, 87
    # Hierarchy: CWE-74 → CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-XSS",
        display_name="Cross-Site Scripting (XSS)",
        slots=[
            Slot("Source", "Untrusted input acquisition — user-controlled data from request, URL, or stored data", True, 0),
            Slot("MissingEncoding", "Missing HTML encoding — input not escaped before insertion into page output", True, 1),
            Slot("Storage", "Malicious data persisted in database, log, or cache (stored XSS)", False, 2),
            Slot("Render", "Output to HTML page context — browser renders attacker-controlled content", True, 3),
            Slot("ScriptExec", "Script execution — browser executes attacker-controlled JavaScript", True, 4),
        ],
        cwe_types=["79", "80", "81", "82", "83", "84", "85", "86", "87", "116"],
        edge_weight_profile=_injection_profile(call_to_exec=3.0),
    ),

    # ------------------------------------------------------------------
    # Injection — Path Traversal
    # Covers: 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41
    # Covers: 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67
    # Hierarchy: CWE-706 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-Path-Traversal",
        display_name="Path Traversal / File Access",
        slots=[
            Slot("Source", "User-controlled path input — filename, directory, or path component from external source", True, 0),
            Slot("BuildPath", "Path construction — concatenating input into file path string", True, 1),
            Slot("MissingValidation", "Missing path sanitization — .. , / separators, or symlinks not checked", True, 2),
            Slot("UnauthorizedAccess", "Access outside restricted directory — read/write/execute unauthorized files", True, 3),
            Slot("Impact", "Information disclosure, file modification, or code execution via file access", True, 4),
        ],
        cwe_types=["22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33",
                    "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45",
                    "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57",
                    "58", "59", "60", "61", "62", "63", "64", "65", "66", "67"],
        edge_weight_profile=_injection_profile(),
    ),

    # ------------------------------------------------------------------
    # Injection — Deserialization
    # Covers: 502
    # Hierarchy: CWE-913 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-Deserialization",
        display_name="Deserialization of Untrusted Data",
        slots=[
            Slot("Source", "Untrusted serialized data — blob, string, or stream from user/network", True, 0),
            Slot("Deserialize", "Deserialization call — unserialize(), readObject(), pickle.loads(), JSON.parse()", True, 1),
            Slot("TypeConfusion", "Missing type validation — attacker-controlled object type or class instantiated", True, 2),
            Slot("Execute", "Gadget chain execution — attacker-controlled method invocations during deserialization", True, 3),
            Slot("Impact", "Remote code execution, data tampering, or denial of service", True, 4),
        ],
        cwe_types=["502"],
        edge_weight_profile=_injection_profile(call_to_exec=4.0),
    ),

    # ------------------------------------------------------------------
    # Injection — XXE
    # Covers: 611, 827
    # Hierarchy: CWE-610 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Injection-XXE",
        display_name="XML External Entity (XXE) Injection",
        slots=[
            Slot("Source", "Untrusted XML input — XML document from user upload, API, or external source", True, 0),
            Slot("ParseXML", "XML parsing — parser processes document with external entity resolution enabled", True, 1),
            Slot("ExternalResolve", "External entity resolution — parser fetches URL or file referenced in DTD/entity", True, 2),
            Slot("Exposure", "Information disclosure or SSRF — file contents exfiltrated or internal service accessed", True, 3),
        ],
        cwe_types=["611", "827"],
        edge_weight_profile=_injection_profile(),
    ),

    # ------------------------------------------------------------------
    # Input Validation
    # Covers: 20, 252, 253, 754
    # Hierarchy: CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Input-Validation",
        display_name="Improper Input Validation",
        slots=[
            Slot("Source", "External input — data from user, network, file, or environment entering the application", True, 0),
            Slot("Validate", "Validation attempt — format check, type check, range check (insufficient)", False, 1),
            Slot("MissingCheck", "Missing or bypassed validation — input passes unchecked or validation is flawed", True, 2),
            Slot("DangerousUse", "Unvalidated input used in security-sensitive operation — memory, command, query, path, etc.", True, 3),
        ],
        cwe_types=["20", "252", "253", "754", "74", "184", "697"],
        edge_weight_profile=_injection_profile(),
    ),

    # ------------------------------------------------------------------
    # Authentication
    # Covers: 287, 288, 289, 290, 291, 294, 295, 296, 297, 298, 302, 303, 304, 305, 306, 307, 308, 309
    # Hierarchy: CWE-284
    # ------------------------------------------------------------------
    Archetype(
        family="Authentication",
        display_name="Improper Authentication",
        slots=[
            Slot("RequestEntry", "Protected request/action — user attempts to access restricted functionality", True, 0),
            Slot("CredentialCheck", "Credential verification — password, token, or certificate validation (flawed)", False, 1),
            Slot("WeakVerification", "Weak or bypassed verification — missing check, hardcoded credential, insufficient validation", True, 2),
            Slot("AuthBypass", "Authentication bypass — attacker gains access without valid credentials", True, 3),
            Slot("ProtectedAccess", "Unauthorized access to protected resource or operation", True, 4),
        ],
        cwe_types=["287", "288", "289", "290", "291", "294", "295", "296", "297", "298",
                    "302", "303", "304", "305", "306", "307", "308", "309", "522"],
        edge_weight_profile=_auth_profile(),
    ),

    # ------------------------------------------------------------------
    # Authorization
    # Covers: 862, 863, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286
    # Hierarchy: CWE-284
    # ------------------------------------------------------------------
    Archetype(
        family="Authorization",
        display_name="Missing or Insufficient Authorization",
        slots=[
            Slot("RequestEntry", "Protected resource request — authenticated user attempts to access resource", True, 0),
            Slot("AuthCheck", "Authorization check — permission/role verification (exists but bypassable)", False, 1),
            Slot("MissingAuth", "Missing authorization — code path where permission check is absent", True, 2),
            Slot("ProtectedOp", "Access to protected resource — read/write/delete without proper authorization", True, 3),
        ],
        cwe_types=["862", "863", "266", "267", "268", "269", "270", "271", "272", "273",
                    "274", "275", "276", "277", "278", "279", "280", "281", "282", "283",
                    "284", "285", "286", "254", "264"],
        edge_weight_profile=_auth_profile(),
    ),

    # ------------------------------------------------------------------
    # Permission
    # Covers: 732, 733, 275, 276, 277
    # Hierarchy: CWE-285 → CWE-284
    # ------------------------------------------------------------------
    Archetype(
        family="Permission",
        display_name="Incorrect Permission Assignment",
        slots=[
            Slot("ResourceSetup", "Resource creation/configuration — file, socket, or object created with permissions", True, 0),
            Slot("WrongPermission", "Overly permissive setting — world-readable, world-writable, or wrong group/owner", True, 1),
            Slot("Exposure", "Unauthorized access — attacker reads, modifies, or executes protected resource", True, 2),
        ],
        cwe_types=["732", "733", "275", "276", "277"],
        edge_weight_profile=_auth_profile(),
    ),

    # ------------------------------------------------------------------
    # Resource Exhaustion / DoS
    # Covers: 400, 770, 835, 674, 617, 834, 20
    # Hierarchy: CWE-664 (400, 770), CWE-691 (835, 674, 617)
    # ------------------------------------------------------------------
    Archetype(
        family="Resource-Exhaustion",
        display_name="Resource Exhaustion / Denial of Service",
        slots=[
            Slot("Source", "External trigger — user input, request, or data that triggers resource consumption", True, 0),
            Slot("Allocation", "Resource allocation — memory, CPU, file descriptors, or threads allocated", True, 1),
            Slot("MissingLimit", "Missing resource limit — no throttle, quota, or bounds on allocation", True, 2),
            Slot("Exhaustion", "Resource exhaustion — memory full, CPU saturated, or handles depleted", True, 3),
            Slot("Impact", "Denial of service — application crash, hang, or unresponsive state", True, 4),
        ],
        cwe_types=["400", "770", "835", "674", "617", "834", "399", "1333"],
        edge_weight_profile={**_DEFAULT_EDGE_WEIGHTS, "data_flow": 1.0, "cfg": 1.0, "call": 1.0},
    ),

    # ------------------------------------------------------------------
    # Information Leak / Exposure
    # Covers: 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213
    # Hierarchy: CWE-668 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Information-Leak",
        display_name="Information Exposure / Leak",
        slots=[
            Slot("Source", "Sensitive data — credentials, keys, PII, memory contents, or system information", True, 0),
            Slot("Read", "Data access — sensitive information read from storage, memory, or configuration", True, 1),
            Slot("Transmit", "Exfiltration path — data sent to log, error message, HTTP response, or network", True, 2),
            Slot("Leak", "Information disclosure — unauthorized actor receives sensitive data", True, 3),
        ],
        cwe_types=["200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
                    "210", "211", "212", "213", "532"],
        edge_weight_profile={**_DEFAULT_EDGE_WEIGHTS, "data_flow": 2.0},
    ),

    # ------------------------------------------------------------------
    # Race Condition / Concurrent Access
    # Covers: 362, 363, 364, 365, 366, 367, 368, 662, 663, 667
    # ------------------------------------------------------------------
    Archetype(
        family="Race-Condition",
        display_name="Race Condition / TOCTOU",
        slots=[
            Slot("Entry", "Concurrent execution entry — multiple threads/processes accessing shared resource", True, 0),
            Slot("CheckPhase", "Check phase — verify resource state (file exists, permission, etc.)", False, 1),
            Slot("TimeWindow", "Time-of-check-to-time-of-use gap — state changes between check and use", True, 2),
            Slot("UsePhase", "Use phase — operate on resource with stale check result", True, 3),
            Slot("Corruption", "Race exploitation — unauthorized access, corruption, or privilege escalation", True, 4),
        ],
        cwe_types=["362", "363", "364", "365", "366", "367", "368", "479", "662", "663", "667"],
        edge_weight_profile={**_DEFAULT_EDGE_WEIGHTS, "cfg": 1.5},
    ),

    # ------------------------------------------------------------------
    # Cryptographic Failures
    # Covers: 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329
    # Covers: 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 343, 344, 345, 346, 347
    # ------------------------------------------------------------------
    Archetype(
        family="Cryptographic-Failure",
        display_name="Cryptographic Failure",
        slots=[
            Slot("CryptoOperation", "Cryptographic operation — encrypt, decrypt, hash, sign, or verify called", True, 0),
            Slot("WeakConfig", "Weak configuration — short key, weak algorithm (MD5, DES), hardcoded key, missing salt", True, 1),
            Slot("Exposure", "Cryptographic bypass — attacker decrypts, forges signatures, or recovers keys", True, 2),
        ],
        cwe_types=["310", "311", "312", "313", "314", "315", "316", "317", "318", "319",
                    "320", "321", "322", "323", "324", "325", "326", "327", "328", "329",
                    "330", "331", "332", "333", "334", "335", "336", "337", "338", "339",
                    "340", "341", "343", "344", "345", "346", "347"],
        edge_weight_profile=_DEFAULT_EDGE_WEIGHTS.copy(),
    ),

    # ------------------------------------------------------------------
    # Web — Cross-Site Request Forgery (CSRF)
    # Covers: 352
    # Hierarchy: CWE-352 → CWE-345 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Web-CSRF",
        display_name="Cross-Site Request Forgery (CSRF)",
        slots=[
            Slot("AuthenticatedSession", "User holds valid authenticated session with target application", True, 0),
            Slot("CraftedRequest", "Attacker crafts malicious request — form, link, or script targeting state-changing action", True, 1),
            Slot("MissingCSRFToken", "Missing or predictable anti-CSRF token — no per-session nonce in request", True, 2),
            Slot("StateChange", "State-changing operation executed — transfer, password change, privilege escalation", True, 3),
            Slot("Impact", "Unauthorized action performed with victim's credentials", True, 4),
        ],
        cwe_types=["352"],
        edge_weight_profile=_web_profile(call_to_web=5.0, call_to_auth_check=3.0),
    ),

    # ------------------------------------------------------------------
    # Web — Untrusted Search Path / DLL Hijacking
    # Covers: 426
    # Hierarchy: CWE-426 → CWE-642 → CWE-668 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Web-Untrusted-Search-Path",
        display_name="Untrusted Search Path / DLL Hijacking",
        slots=[
            Slot("ExternalPath", "External or user-controlled search path — PATH, LD_LIBRARY_PATH, working directory", True, 0),
            Slot("PathResolution", "Binary/library resolution — search path traversed, attacker-controlled location checked first", True, 1),
            Slot("LoadUntrusted", "Untrusted binary/library loaded — DLL, .so, .dylib from attacker-writable location", True, 2),
            Slot("Execute", "Code execution in process context — attacker code runs with application privileges", True, 3),
        ],
        cwe_types=["426"],
        edge_weight_profile=_web_profile(call_to_exec=5.0),
    ),

    # ------------------------------------------------------------------
    # Web — Unrestricted File Upload
    # Covers: 434
    # Hierarchy: CWE-434 → CWE-669 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Web-Unrestricted-File-Upload",
        display_name="Unrestricted File Upload",
        slots=[
            Slot("Upload", "File upload accepted — multipart form, PUT, or WebSocket file transfer", True, 0),
            Slot("MissingTypeCheck", "Missing file type/content validation — extension, MIME, magic bytes not verified", True, 1),
            Slot("StoreAndAccess", "Uploaded file stored in web-accessible path — can be requested via URL", True, 2),
            Slot("Execute", "Server executes or interprets uploaded file — PHP, JSP, ASPX, or script via include", True, 3),
            Slot("Impact", "Remote code execution, XSS, or phishing via uploaded content", True, 4),
        ],
        cwe_types=["434"],
        edge_weight_profile=_web_profile(call_to_exec=5.0),
    ),

    # ------------------------------------------------------------------
    # Web — HTTP Request Smuggling
    # Covers: 444
    # Hierarchy: CWE-444 → CWE-436 → CWE-707
    # ------------------------------------------------------------------
    Archetype(
        family="Web-HTTP-Request-Smuggling",
        display_name="HTTP Request Smuggling / Request Splitting",
        slots=[
            Slot("CraftedRequest", "Malformed HTTP request — ambiguous Content-Length / Transfer-Encoding headers", True, 0),
            Slot("HeaderParsing", "Differential header parsing — front-end and back-end parse request boundaries differently", True, 1),
            Slot("RequestSmuggling", "Smuggled request prepended to next user request — poison web cache or bypass filters", True, 2),
            Slot("Impact", "Cache poisoning, credential hijacking, or security control bypass", True, 3),
        ],
        cwe_types=["444"],
        edge_weight_profile=_web_profile(),
    ),

    # ------------------------------------------------------------------
    # Web — Download of Code Without Integrity Check
    # Covers: 494
    # Hierarchy: CWE-494 → CWE-345 → CWE-664 and CWE-669
    # ------------------------------------------------------------------
    Archetype(
        family="Web-Download-Without-Integrity",
        display_name="Download of Code Without Integrity Check",
        slots=[
            Slot("RemoteSource", "Remote code source — URL or external server specified for download", True, 0),
            Slot("Download", "Code download — fetch executable, library, or script from remote source", True, 1),
            Slot("MissingIntegrityCheck", "Missing integrity verification — no checksum, signature, or certificate validation", True, 2),
            Slot("Execute", "Code installation and execution — downloaded artifact runs with application privileges", True, 3),
            Slot("Impact", "Malicious code execution via compromised source or MITM", True, 4),
        ],
        cwe_types=["494"],
        edge_weight_profile=_web_profile(call_to_exec=5.0),
    ),

    # ------------------------------------------------------------------
    # Web — Open Redirect
    # Covers: 601
    # Hierarchy: CWE-601 → CWE-610 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Web-Open-Redirect",
        display_name="URL Redirection to Untrusted Site (Open Redirect)",
        slots=[
            Slot("UserURLInput", "User-controlled redirect target — URL parameter, Referer, or form input", True, 0),
            Slot("MissingValidation", "Missing URL whitelist validation — no safe-list check on redirect destination", True, 1),
            Slot("BuildRedirect", "Redirect response constructed — Location header or meta-refresh with attacker URL", True, 2),
            Slot("Redirect", "Browser follows redirect to malicious site — phishing, malware, or credential theft", True, 3),
        ],
        cwe_types=["601"],
        edge_weight_profile=_web_profile(call_to_web=5.0),
    ),

    # ------------------------------------------------------------------
    # Web — Server-Side Request Forgery (SSRF)
    # Covers: 918
    # Hierarchy: CWE-918 → CWE-441 → CWE-610 → CWE-664
    # ------------------------------------------------------------------
    Archetype(
        family="Web-SSRF",
        display_name="Server-Side Request Forgery (SSRF)",
        slots=[
            Slot("UserURLInput", "User-controlled URL or fetch target — request parameter, body, or header", True, 0),
            Slot("MissingFilter", "Missing internal host filter — no blocklist/allowlist for internal IPs, metadata endpoints", True, 1),
            Slot("FetchURL", "Server fetches attacker-specified URL — HTTP client, curl, or file_get_contents", True, 2),
            Slot("InternalAccess", "Access internal service or metadata — cloud metadata, internal API, port scan", True, 3),
            Slot("Impact", "Information disclosure, privilege escalation, or remote code execution via internal pivot", True, 4),
        ],
        cwe_types=["918"],
        edge_weight_profile=_web_profile(call_to_web=5.0),
    ),

    # ------------------------------------------------------------------
    # Generic / Catch-all
    # For any CWE not covered by specific families above.
    # ------------------------------------------------------------------
    Archetype(
        family="Generic",
        display_name="Generic Vulnerability",
        slots=[
            Slot("Source", "Untrusted or external input/data entering the application", True, 0),
            Slot("Manipulation", "Data processing or transformation — the vulnerable operation or missing safeguard", True, 1),
            Slot("Sink", "Dangerous operation or consequence — crash, corruption, leak, or unauthorized access", True, 2),
        ],
        cwe_types=[],  # catch-all — any unmatched CWE falls here
        edge_weight_profile={**_DEFAULT_EDGE_WEIGHTS},
    ),
]


# ============================================================================
# Lookup tables (built at import time)
# ============================================================================

# CWE-ID (without prefix) → Archetype
_CWE_TO_ARCHETYPE: Dict[str, Archetype] = {}
for arch in ARCHETYPE_LIBRARY:
    for cwe in arch.cwe_types:
        cwe_clean = cwe.strip().lstrip("0") or cwe.strip()  # normalize
        _CWE_TO_ARCHETYPE[cwe.strip()] = arch
        if cwe_clean != cwe.strip():
            _CWE_TO_ARCHETYPE[cwe_clean] = arch

# Family name → Archetype
_FAMILY_TO_ARCHETYPE: Dict[str, Archetype] = {a.family: a for a in ARCHETYPE_LIBRARY}

# The generic archetype (fallback)
_GENERIC_ARCHETYPE = _FAMILY_TO_ARCHETYPE["Generic"]


def get_archetype(cwe_id: str) -> Archetype:
    """Look up archetype by CWE-ID.

    Args:
        cwe_id: CWE-ID string, with or without "CWE-" prefix.
                e.g., "CWE-787", "787", "cwe-120"

    Returns:
        Archetype for the CWE type, or Generic archetype if unmatched.
    """
    clean = cwe_id.upper().replace("CWE-", "").replace("CWE", "").strip()
    # Try exact match first
    if clean in _CWE_TO_ARCHETYPE:
        return _CWE_TO_ARCHETYPE[clean]
    # Try zero-padded variants (e.g., "20" → "020" — unlikely but safe)
    for padded in (clean.zfill(3), clean.zfill(4)):
        if padded in _CWE_TO_ARCHETYPE:
            return _CWE_TO_ARCHETYPE[padded]
    return _GENERIC_ARCHETYPE


def get_archetype_by_family(family: str) -> Optional[Archetype]:
    """Look up archetype by family name."""
    return _FAMILY_TO_ARCHETYPE.get(family)


def list_families() -> List[str]:
    """List all registered CWE family names."""
    return [a.family for a in ARCHETYPE_LIBRARY]


def list_cwe_coverage() -> Dict[str, int]:
    """Return {family: count_of_covered_CWEs} for all families."""
    return {a.family: len(a.cwe_types) for a in ARCHETYPE_LIBRARY}
