# frozen_string_literal: true

# Build-time AES-256-GCM encryption for password-protected writeups.
#
# For any document in the :writeups collection with a `password:` frontmatter
# field, the rendered `.prose.prose-wide` block is replaced with a lock form +
# encrypted blob. The client decrypts in-browser via Web Crypto API using the
# password the visitor types.
#
# Crypto parameters (must match the client JS):
#   - PBKDF2-HMAC-SHA256, 200,000 iterations
#   - AES-256-GCM, 12-byte IV, 16-byte auth tag
#   - 16-byte random salt per writeup
#
# The password NEVER appears in the built site. It lives only in the private
# hack-the-box-writeups source repo; sync_writeups.rb copies it into Jekyll
# frontmatter at build time; this plugin uses it to derive the key, encrypt
# the HTML, then the frontmatter is discarded when Jekyll writes output.

require "openssl"
require "base64"
require "securerandom"
require "cgi"
require_relative "../scripts/lock_marker"

module EncryptWriteups
  # OWASP ASVS v4 (2023) recommends ≥600k iterations for PBKDF2-HMAC-SHA256.
  # Client derives the key on the fly, so bumping this is safe — the `iter`
  # value rides in the blob's dataset. Adds ~0.6s to first unlock on mobile.
  PBKDF2_ITERATIONS = 600_000
  KEY_BYTES   = 32 # AES-256
  SALT_BYTES  = 16
  IV_BYTES    = 12 # GCM standard

  DEFAULT_HINT = "Contact me on Discord or LinkedIn for the password."

  # The full-page regex that locates the rendered prose block produced by
  # _layouts/writeup.html. Matches the opening <div class="prose prose-wide">
  # through the closing </div> just before the <footer class="writeup-footer">.
  PROSE_REGEX = %r{
    (<div\s+class="prose\s+prose-wide">)
    (.*?)
    (</div>\s*<footer\s+class="writeup-footer")
  }mx

  module_function

  def encrypt_html(plaintext, password)
    salt = SecureRandom.random_bytes(SALT_BYTES)
    iv   = SecureRandom.random_bytes(IV_BYTES)
    key  = OpenSSL::KDF.pbkdf2_hmac(
      password,
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      length: KEY_BYTES,
      hash: "sha256",
    )

    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = key
    cipher.iv  = iv
    ciphertext = cipher.update(plaintext) + cipher.final
    tag = cipher.auth_tag

    {
      salt: Base64.strict_encode64(salt),
      iv:   Base64.strict_encode64(iv),
      # Web Crypto API expects ciphertext||tag as a single buffer for AES-GCM.
      ct:   Base64.strict_encode64(ciphertext + tag),
      iter: PBKDF2_ITERATIONS,
    }
  end

  def build_lock_markup(blob, hint, partial: false)
    safe_hint = CGI.escapeHTML(hint)
    section_class = partial ? "writeup-lock writeup-lock-partial" : "writeup-lock"
    title = partial ? "The rest of this writeup is locked" : "This writeup is locked"
    heading_tag = partial ? "h3" : "h2"
    <<~HTML
      <div class="#{section_class}"
           data-salt="#{blob[:salt]}"
           data-iv="#{blob[:iv]}"
           data-iter="#{blob[:iter]}"
           data-ciphertext="#{blob[:ct]}">
        <div class="lock-card">
          <div class="lock-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
          </div>
          <#{heading_tag} class="lock-title">#{title}</#{heading_tag}>
          <p class="lock-hint">#{safe_hint}</p>
          <a class="lock-discord" href="https://discord.com/users/1324242337500762152" target="_blank" rel="noopener">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
              <path d="M20.317 4.369A19.791 19.791 0 0 0 16.558 3a.074.074 0 0 0-.079.038c-.17.304-.356.699-.487 1.012a18.27 18.27 0 0 0-5.486 0c-.13-.32-.32-.708-.492-1.012A.077.077 0 0 0 9.935 3a19.736 19.736 0 0 0-3.76 1.369.07.07 0 0 0-.032.027C2.533 9.046 1.642 13.58 2.078 18.057a.082.082 0 0 0 .031.056 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.995a.076.076 0 0 0-.042-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .077-.01c3.927 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.009c.12.099.246.198.373.292a.077.077 0 0 1-.006.128 12.299 12.299 0 0 1-1.873.891.077.077 0 0 0-.041.107c.36.7.772 1.364 1.225 1.994a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.331c-1.182 0-2.157-1.086-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.419 0 1.333-.956 2.419-2.157 2.419zm7.975 0c-1.183 0-2.157-1.086-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.419 0 1.333-.946 2.419-2.157 2.419z"/>
            </svg>
            <span>Contact on Discord</span>
          </a>
          <form class="lock-form" autocomplete="off">
            <input type="password"
                   class="lock-input"
                   name="password"
                   placeholder="Enter password"
                   aria-label="Writeup password"
                   autocomplete="off"
                   spellcheck="false"
                   required>
            <button type="submit" class="lock-submit">Unlock</button>
          </form>
          <p class="lock-error" role="alert" hidden></p>
          <noscript>
            <p class="lock-noscript">
              JavaScript is required to decrypt this writeup. Please enable JavaScript, or contact me on Discord for a plaintext copy.
            </p>
          </noscript>
          <p class="lock-disclaimer">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
            <span>HackTheBox policy restricts publishing walkthroughs for active-season machines. This writeup is password-protected to respect that policy while keeping the content available to those who already have access.</span>
          </p>
        </div>
      </div>
    HTML
  end
end

Jekyll::Hooks.register :writeups, :post_render do |doc|
  password = doc.data["password"]
  next if password.nil? || password.to_s.strip.empty?

  html = doc.output
  match = html.match(EncryptWriteups::PROSE_REGEX)
  unless match
    Jekyll.logger.warn "encrypt_writeups:", "prose block not found in #{doc.relative_path} — skipping"
    next
  end

  open_div, inner_html, tail = match[1], match[2], match[3]
  hint = doc.data["password_hint"] || EncryptWriteups::DEFAULT_HINT

  # Partial lock: if the author placed `<!-- lock -->` in the source, split the
  # rendered prose at that marker. Everything before stays public; everything
  # after gets encrypted and replaced with an inline lock card.
  if inner_html =~ ::LockMarker::REGEX
    parts = inner_html.split(::LockMarker::REGEX, -1)
    if parts.length > 2
      Jekyll.logger.warn "encrypt_writeups:",
                         "multiple <!-- lock --> markers in #{doc.relative_path} — " \
                         "only the first splits; content between markers stays public"
    end
    preview_html = parts.first
    locked_html  = parts.drop(1).join
    blob = EncryptWriteups.encrypt_html(locked_html, password.to_s)
    lock = EncryptWriteups.build_lock_markup(blob, hint, partial: true)

    # Use block form of sub so backslash sequences in the replacement (\0, \1,
    # \& — common in code blocks containing regex or pwntools escapes) are
    # treated as literal characters instead of regex backreferences.
    replacement = "#{open_div}#{preview_html}\n<div class=\"writeup-locked-section\">\n#{lock}\n</div>\n</div>\n\n  #{tail}"
    doc.output = html.sub(EncryptWriteups::PROSE_REGEX) { replacement }
    next
  end

  # Full-page lock: no marker, encrypt the whole prose block.
  blob = EncryptWriteups.encrypt_html(inner_html, password.to_s)
  lock = EncryptWriteups.build_lock_markup(blob, hint)

  replacement = "#{open_div}\n#{lock}\n</div>\n\n  #{tail}"
  doc.output = html.sub(EncryptWriteups::PROSE_REGEX) { replacement }
end

# Belt-and-suspenders: scrub `password` from any JSON-like data blocks we might
# accidentally emit downstream. Currently a no-op since no template reads it,
# but cheap insurance against future footguns.
Jekyll::Hooks.register :writeups, :post_write do |doc|
  next unless doc.data["password"]
  doc.data.delete("password")
end
