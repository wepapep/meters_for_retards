"""
landis_gyr_aliases.py — Friendly-name aliases for L+G object names.

Maps short, human-friendly names to the official L+G object names found in
the XML catalogues. The catalogue-lookup chain is:

    user calls m.read("serial_number")
      → look up alias  → "StringRegisterID2_1"
      → look up name in variant catalogue → short code (e.g. 0x40E0)
      → SN read at that code

Aliases are vendor-curated and intentionally small. Users who want exhaustive
access should use the official L+G names directly.
"""

ALIASES: dict[str, str] = {
    # Identification
    "serial_number":          "StringRegisterID2_1",
    "device_identification":  "StringRegisterConfigId",
    "software_id":            "StringRegisterSoftwareId",
    "dlms_device_name":       "StringRegisterDLMSDeviceId",
    "device_id_1":            "Option1IdentCopy",

    # Add more as common needs emerge.
}
