#!/usr/bin/env ruby
# Sync Hack-The-Box writeups from an external repo into this Jekyll site.
#
# Reads markdown writeups from WRITEUPS_SOURCE_DIR (env, default:
# /home/akash/exe/hack-the-box-writeups) and produces Jekyll-formatted files in
# ./_writeups/<slug>.md. Auto-generates frontmatter by parsing the writeup H1
# and Machine Info block, strips those metadata blocks from the body, and
# applies the redaction rules from scripts/redactions.yml.
#
# Idempotent: rerunning overwrites existing files but never touches source.
# If a source markdown already has YAML frontmatter, it is respected and the
# auto-parser is skipped (escape hatch for one-off overrides).

require "yaml"
require "fileutils"
require "set"
require "time"
require "open3"
require_relative "lock_marker"

SITE_ROOT     = File.expand_path("..", __dir__)
DEFAULT_SOURCE = "/home/akash/exe/hack-the-box-writeups"
SOURCE_DIR    = ENV["WRITEUPS_SOURCE_DIR"] || DEFAULT_SOURCE
TARGET_DIR    = File.join(SITE_ROOT, "_writeups")
REDACTIONS_FILE = File.join(SITE_ROOT, "scripts/redactions.yml")

# --- Redaction engine ---------------------------------------------------------

def load_redactions
  return { "literal" => {}, "regex" => [] } unless File.exist?(REDACTIONS_FILE)
  YAML.load_file(REDACTIONS_FILE) || {}
end

def redact(text, rules)
  (rules["literal"] || {}).each do |needle, replacement|
    text = text.gsub(needle, replacement)
  end
  (rules["regex"] || []).each do |r|
    re = Regexp.new(r["pattern"], Regexp::MULTILINE)
    text = text.gsub(re, r["replacement"])
  end
  text
end

# --- Header parsing -----------------------------------------------------------

# Format A: "# HackTheBox - Name Writeup" + **Machine:** / **IP Address:** / **Difficulty:** / **OS:** bullets
# Format B: "# Name - Hack The Box Writeup (Difficulty - OS)" + ## Machine Info list
def parse_header(raw)
  meta = { "title" => nil, "difficulty" => nil, "os" => nil, "ip" => nil, "hostname" => nil, "cves" => [], "password" => nil, "category" => nil }
  h1 = raw.lines.find { |l| l.start_with?("# ") }
  return meta unless h1

  h1_text = h1.sub(/^#\s*/, "").strip

  # Format B: "Name - Hack The Box Writeup (Difficulty - OS)"
  if (m = h1_text.match(/\A(.+?)\s*[-–]\s*Hack The Box Writeup\s*\((.+?)\s*[-–]\s*(.+?)\)/i))
    meta["title"]      = m[1].strip
    meta["difficulty"] = m[2].strip
    meta["os"]         = m[3].strip
  # Format A: "HackTheBox - Name Writeup"
  elsif (m = h1_text.match(/\AHackTheBox\s*[-–]\s*(.+?)\s+Writeup/i))
    meta["title"] = m[1].strip
  else
    meta["title"] = h1_text
  end

  # Pull **Key:** value pairs from the top ~40 lines (covers both formats)
  top = raw.lines.first(50).join
  {
    "name"        => /^\s*[-*]?\s*\*\*Name:\*\*\s*(.+?)\s*$/i,
    "os"          => /^\s*[-*]?\s*\*\*OS:\*\*\s*(.+?)\s*$/i,
    "difficulty"  => /^\s*[-*]?\s*\*\*Difficulty:\*\*\s*(.+?)\s*$/i,
    "ip_address"  => /^\s*[-*]?\s*\*\*IP(?:\s*Address)?:\*\*\s*(.+?)\s*$/i,
    "hostname"    => /^\s*[-*]?\s*\*\*Hostname:\*\*\s*(.+?)\s*$/i,
    "cves"        => /^\s*[-*]?\s*\*\*CVEs?:\*\*\s*(.+?)\s*$/i,
    "password"    => /^\s*[-*]?\s*\*\*Password:\*\*\s*(.+?)\s*$/i,
    "category"    => /^\s*[-*]?\s*\*\*Category:\*\*\s*(.+?)\s*$/i,
  }.each do |key, rx|
    next unless (m = top.match(rx))
    meta["title"]      = m[1].strip if key == "name"
    meta["os"]         = m[1].strip if key == "os" && meta["os"].nil?
    meta["difficulty"] = m[1].strip if key == "difficulty" && meta["difficulty"].nil?
    meta["ip"]         = m[1].strip if key == "ip_address"
    meta["hostname"]   = m[1].strip if key == "hostname"
    meta["cves"]       = m[1].split(",").map(&:strip) if key == "cves"
    meta["password"]   = m[1].strip if key == "password"
    meta["category"]   = m[1].strip.upcase if key == "category"
  end

  meta["difficulty"] = nil if meta["difficulty"] =~ /unavailable/i
  meta
end

# Scan the body for `<!-- lock -->` markers that are NOT on their own top-level
# line (i.e., inside a fenced code block, or with content on the same line).
# The encrypt plugin splits rendered HTML on the marker; if the marker lands
# inside a <pre> or mid-element, the split produces malformed output. Warn at
# sync time so the author can move the marker before deploying.
def validate_lock_marker_placement(body, source_path)
  in_fence = false
  fence_re = /\A\s*(```+|~~~+)/
  body.each_line.with_index(1) do |line, lineno|
    if line =~ fence_re
      in_fence = !in_fence
      next
    end
    next unless line =~ LockMarker::REGEX
    if in_fence
      warn "sync_writeups: #{source_path}:#{lineno} `<!-- lock -->` inside a fenced code block — will produce broken output; move to top level"
    elsif line.strip !~ /\A<!--\s*lock\s*-->\z/i
      warn "sync_writeups: #{source_path}:#{lineno} `<!-- lock -->` shares a line with other content — move to its own line"
    end
  end
end

# Strip the `**Machine:** ...` block (Format A) or the whole `## Machine Info`
# section (Format B) from the body. Also removes the leading H1 line — we render
# title via frontmatter + layout instead.
def strip_metadata_blocks(body)
  lines = body.lines
  out = []
  i = 0
  # Drop leading H1
  while i < lines.length && lines[i].strip.empty?; out << lines[i]; i += 1; end
  i += 1 if i < lines.length && lines[i].start_with?("# ")

  in_machine_info = false
  in_format_a_block = false

  while i < lines.length
    line = lines[i]

    # Format B: "## Machine Info" (consume until next ## / ---)
    if line =~ /^\s*##\s+Machine Info\b/i
      in_machine_info = true
      i += 1
      next
    end
    if in_machine_info
      if line =~ /\A\s*##\s+\S/ || line.strip == "---"
        in_machine_info = false
        # drop trailing --- separator too
        i += 1 if line.strip == "---"
        next
      end
      i += 1
      next
    end

    # Format A: consecutive **Machine:** / **IP Address:** / **Difficulty:** / **OS:** lines
    if line =~ /^\s*\*\*(Machine|IP Address|IP|Difficulty|OS|Hostname|Domain|CVEs?|Password):\*\*/i
      in_format_a_block = true
      i += 1
      next
    end
    if in_format_a_block
      # End when we hit a blank line OR an --- separator OR a real heading
      if line.strip.empty? || line.strip == "---" || line =~ /^#/
        in_format_a_block = false
        # consume the --- if that's what ended it
        i += 1 if line.strip == "---"
        next if line.strip.empty? || line.strip == "---"
      else
        i += 1
        next
      end
    end

    out << line
    i += 1
  end

  out.join.sub(/\A\s+/, "")
end

# --- Derived metadata ---------------------------------------------------------

def slugify(s)
  s.to_s.downcase.strip.gsub(/[^a-z0-9]+/, "-").gsub(/^-|-$/, "")
end

def normalize_difficulty(d)
  return nil if d.nil?
  case d.strip.downcase
  when /easy/    then "EASY"
  when /medium/  then "MEDIUM"
  when /hard/    then "HARD"
  when /insane/  then "INSANE"
  end
end

def normalize_os(raw)
  return nil if raw.nil?
  s = raw.strip
  return "Windows" if s =~ /windows/i
  return "Linux"   if s =~ /linux/i
  s
end

SEASON_LABELS = {
  "Season - 10" => "HTB Season 10",
  "Season - 8"  => "HTB Season 8",
  "Fortress"    => "HTB Fortress",
}

def season_from_dir(dir)
  trimmed = dir.to_s.strip
  SEASON_LABELS[trimmed] || trimmed
end

# Minimal category heuristic for CTF categories. Most HTB machines are a mix,
# so default to MISC. Prefer explicit frontmatter overrides for accuracy.
CATEGORY_SIGNALS = {
  "WEB"       => %w[ssrf sql injection xss ssti rce via web api endpoint graphql jwt csrf deserialization idor lfi],
  "PWN"       => %w[buffer overflow rop pwntools heap-overflow format-string binary-exploit],
  "CRYPTO"    => %w[rsa aes-ecb cipher crypto ctf decryption],
  "REV"       => %w[ghidra ida-pro reverse-engineer disassembl],
  "FORENSICS" => %w[pcap memory-forensics volatility wireshark packet-capture],
}

# Machine Info **Category:** override must be one of these. Anything else is
# dropped with a warning so a typo doesn't produce a nonsense category badge.
CATEGORY_WHITELIST = (CATEGORY_SIGNALS.keys + %w[AD MISC]).freeze

def detect_category(body)
  lowered = body.downcase
  scores = CATEGORY_SIGNALS.each_with_object({}) do |(cat, signals), h|
    h[cat] = signals.count { |s| lowered.include?(s) }
  end
  best = scores.max_by { |_, v| v }
  return "MISC" if best.nil? || best[1] == 0
  best[0]
end

def extract_tags(source_text, _meta)
  # CVE identifiers are deliberately excluded from public tags — they are
  # high-signal attack indicators for crawlers/search engines. Keep technique
  # tags only; CVE numbers stay in the body prose for readers who unlock.
  # Callers must pass only the public preview (content before `<!-- lock -->`);
  # passing the full body would leak attack techniques from the gated section.
  tags = []
  {
    "SSRF" => /\bssrf\b/i,
    "RCE"  => /\brce\b/i,
    "LFI"  => /\blfi\b/i,
    "SQLi" => /\bsql\s?injection\b|\bsqli\b/i,
    "XSS"  => /\bxss\b/i,
    "SSTI" => /\bssti\b/i,
    "Kerberoasting" => /kerberoast/i,
    "AS-REP-Roasting" => /as-?rep.?roast/i,
    "DCSync" => /dcsync/i,
    "Active Directory" => /active directory|kerberos|bloodhound/i,
    "Docker" => /\bdocker\b/i,
    "Kubernetes" => /kubernetes|kubectl/i,
  }.each { |tag, rx| tags << tag if source_text =~ rx }
  tags.uniq
end

def first_commit_date(source_path)
  out, _, status = Open3.capture3(
    "git", "log", "--diff-filter=A", "--follow", "--format=%aI", "--", source_path,
    chdir: SOURCE_DIR
  )
  return nil unless status.success?
  out.lines.last&.strip
end

# --- Main ---------------------------------------------------------------------

def process_file(source_path, rules)
  raw = File.read(source_path)

  # Escape hatch: if the file already has frontmatter, respect it.
  if raw.start_with?("---\n")
    return { path: source_path, skip: true, reason: "source already has frontmatter" }
  end

  validate_lock_marker_placement(raw, source_path)

  meta = parse_header(raw)
  season = season_from_dir(File.basename(File.dirname(source_path)))
  title = meta["title"] || File.basename(source_path, ".md")
  slug  = slugify(title)

  body = strip_metadata_blocks(raw)
  body = redact(body, rules)

  date_iso = first_commit_date(source_path) || File.mtime(source_path).iso8601
  date = Time.parse(date_iso).strftime("%Y-%m-%d")

  # Only run frontmatter extractors on the public preview. Anything after
  # <!-- lock --> is encrypted at build time and must not leak via tags/
  # description/category — those render unconditionally outside the encrypted
  # prose block (footer tags, JSON-LD keywords, article:tag meta, hero-desc,
  # og:description).
  preview = body.split(LockMarker::REGEX, 2).first.to_s

  # Category resolution: Machine Info **Category:** override wins (if it's in
  # the whitelist — otherwise drop with a warning). Otherwise infer from
  # preview keywords. Falling back to MISC when the preview is empty (lock
  # marker at top) is misleading — require an author override in that case.
  override = meta["category"]
  if override && !override.empty? && !CATEGORY_WHITELIST.include?(override)
    warn "sync_writeups: unknown **Category:** '#{override}' in #{source_path} — dropping; use one of #{CATEGORY_WHITELIST.join(', ')}"
    override = nil
  end
  category =
    if override
      override
    elsif preview.strip.empty?
      nil
    else
      detect_category(preview)
    end

  difficulty = normalize_difficulty(meta["difficulty"])
  os_label = normalize_os(meta["os"])

  description = preview.split(/\n{2,}/).find { |p|
    stripped = p.strip
    next false if stripped.empty?
    next false if stripped.start_with?("#", "```", "|", ">", "- ", "* ", "-[", "[", "---")
    next false if stripped =~ /\A\s*\d+\.\s/             # ordered list
    next false if stripped.lines.all? { |l| l =~ /\A\s*[-*]\s/ }  # all-bullet block
    stripped.length > 60
  }.to_s.strip.tr("\n", " ").gsub(/\s+/, " ")[0, 220]

  # Safe fallback when the preview is too thin (e.g., lock marker immediately
  # after the machine-info block) — don't reach into the locked region.
  if description.to_s.strip.empty? && meta["password"]
    description = "#{title} — HackTheBox #{difficulty || 'machine'} writeup. Full exploitation details password-protected."
  end

  frontmatter = {
    "layout"      => "writeup",
    "title"       => title,
    "slug"        => slug,
    "category"    => category,
    "difficulty"  => difficulty,
    "os"          => os_label,
    "ip"          => meta["ip"],
    "hostname"    => meta["hostname"],
    "season"      => season,
    "date"        => date,
    "description" => description,
    "password"    => meta["password"],
    "tags"        => extract_tags(preview, meta),
  }.compact

  # Empty-array cleanup (YAML dumps them as `tags: []` otherwise, which is fine,
  # but drop if we literally found nothing)
  frontmatter.delete("tags") if frontmatter["tags"].is_a?(Array) && frontmatter["tags"].empty?

  out_path = File.join(TARGET_DIR, "#{slug}.md")
  content = frontmatter.to_yaml(line_width: 120) + "---\n\n" + body.strip + "\n"

  { path: source_path, out: out_path, content: content, title: title, season: season, difficulty: difficulty, category: category }
end

def main
  unless Dir.exist?(SOURCE_DIR)
    warn "Source dir not found: #{SOURCE_DIR}"
    warn "Set WRITEUPS_SOURCE_DIR to override."
    exit 1
  end

  FileUtils.mkdir_p(TARGET_DIR)

  rules = load_redactions
  sources = Dir.glob(File.join(SOURCE_DIR, "**/*.md")).reject do |p|
    File.basename(p) == "README.md" || p.include?("/.git/")
  end

  # Parse all sources first; only touch disk if every source parses cleanly.
  # A mid-run failure under the old "delete everything, then write each" order
  # could deploy a site with zero writeups.
  results = sources.map do |src|
    begin
      process_file(src, rules)
    rescue => e
      { path: src, error: e.message }
    end
  end

  err = results.select { |r| r[:error] }
  unless err.empty?
    warn "Errors (no _writeups files modified):"
    err.each { |r| warn "  #{r[:path]}: #{r[:error]}" }
    exit 1
  end

  ok   = results.reject { |r| r[:skip] }
  skip = results.select { |r| r[:skip] }

  # Write all fresh content first, then delete any stale target files that
  # weren't re-written (sources that were removed from the source repo).
  # If any write fails mid-loop, abort before deleting anything — leaving the
  # previous _writeups snapshot intact rather than a half-populated dir.
  written = []
  begin
    ok.each do |r|
      File.write(r[:out], r[:content])
      written << r[:out]
    end
  rescue => e
    warn "sync_writeups: File.write failed after #{written.size}/#{ok.size} writeups (#{e.class}: #{e.message})"
    warn "  aborting before stale-file deletion to preserve previous snapshot."
    exit 1
  end
  new_paths = written.to_set

  # Leaves `_`-prefixed hand-crafted overrides alone.
  Dir.glob(File.join(TARGET_DIR, "*.md")).each do |f|
    next if File.basename(f).start_with?("_")
    next if new_paths.include?(f)
    File.delete(f)
  end

  puts "Synced #{ok.size} writeup(s) → #{TARGET_DIR}"
  ok.group_by { |r| r[:season] }.each do |season, items|
    puts "  #{season}:"
    items.sort_by { |r| r[:title].to_s }.each do |r|
      printf "    %-20s %-8s %-8s\n", r[:title], (r[:difficulty] || "?"), (r[:category] || "?")
    end
  end
  unless skip.empty?
    puts "Skipped (pre-existing frontmatter):"
    skip.each { |r| puts "  #{r[:path]}" }
  end
end

main if $PROGRAM_NAME == __FILE__
