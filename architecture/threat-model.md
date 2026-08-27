# Threat Model

The first release treats every connection as a trust boundary and evaluates the target component's declared properties. Internet-facing components, public storage, sensitive data, authentication, and permissions change the resulting severity.

Each finding contains an asset, STRIDE category, CWE identifier, attack path, rationale, recommended control, validation action, and numeric score. Findings are sorted by score so the report starts with the most consequential work.
