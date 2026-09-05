SeaVault Fast logo assets

Files:
- logo.png: full horizontal logo for the application header.
- icon.png: square front icon extracted from the logo for app icon and web icon use.
- favicon.ico: browser favicon containing multiple icon sizes.
- favicon-32.png, favicon-64.png, favicon-180.png: PNG web icon variants.

Recommended repo destination:
internal/webui/assets/

Recommended compile approach:
Use Go embed in internal/webui/server.go so the assets are baked into the final SeaVault binary.


Branding restriction:
These logo, icon, and favicon files are reserved branding assets. They are not licensed under the Apache License and may not be copied, modified, redistributed, embedded, displayed, or used in forks, derivative works, redistributed builds, hosted services, package metadata, marketing, domains, or user interfaces without prior written permission from the rights holder. Forks and redistributed builds must remove or replace these assets before publication or distribution.
