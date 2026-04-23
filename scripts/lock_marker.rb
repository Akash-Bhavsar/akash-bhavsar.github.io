# frozen_string_literal: true

# Shared lock marker definition.
#
# Loaded by both _plugins/encrypt_writeups.rb (build-time encryption) and
# scripts/sync_writeups.rb (frontmatter extraction). Centralizing prevents
# drift — if these regexes ever disagreed, the sync script could leak
# post-lock content into tags/description while the plugin still encrypted it.
#
# Authors write `<!-- lock -->` on its own line in the source markdown;
# kramdown passes it through the rendered HTML verbatim.

module LockMarker
  REGEX = /<!--\s*lock\s*-->/i
end
