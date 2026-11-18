#!/usr/local/bin/ruby2.6
# coding: utf-8
#
# Papyru（WYSIWYG エディタ）— Googleアカウントログイン付き
# ロリポップ！レンタルサーバー（Ruby CGI）向け。標準ライブラリのみ使用。
#
# 設置:
#   1. index.cgi と config.json を同じディレクトリに置く（例: public_html/papyru/）
#   2. パーミッション: index.cgi は 700 / config.json は 600 / ディレクトリは 705
#   3. 1行目のshebangは契約サーバーに合わせて変更
#   4. Google Cloud Console で OAuth クライアント（ウェブ アプリケーション）を作成し、
#      承認済みのリダイレクト URI に config.json の redirect_uri を登録
#   5. https://（ドメイン）/papyru/index.cgi を開く
#
require 'cgi'
require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'uri'

BASE_DIR       = File.expand_path(File.dirname(__FILE__))
DATA_DIR       = File.join(BASE_DIR, 'data')
CONFIG_PATH    = File.join(BASE_DIR, 'config.json')
NAME_RE        = /\A[A-Za-z0-9_\-]{1,50}\z/
MAX_BYTES      = 1_000_000
SESSION_TTL    = 12 * 3600
STATE_TTL      = 600
SESSION_COOKIE = 'papyru_session'
STATE_COOKIE   = 'papyru_oauth_state'
RETURN_COOKIE  = 'papyru_return'   # ログイン後に戻るページのID
ALLOWED_TAGS   = %w[p br b strong i em u s h1 h2 h3 ul ol li blockquote a span div hr pre code
                    table thead tbody tr th td].freeze
# ブラウザが打ち消し線に使う別名タグは <s> にそろえる
TAG_ALIASES    = { 'strike' => 's', 'del' => 's' }.freeze

# ---------- 設定 ----------

def config
  @config ||= JSON.parse(File.read(CONFIG_PATH, encoding: 'utf-8'))
end

def allowed?(email)
  return false if email.to_s.empty?
  Array(config['allowed_emails']).map { |e| e.to_s.downcase }.include?(email.downcase)
end

# ---------- 署名付きトークン（セッション用） ----------

def sign(data)
  OpenSSL::HMAC.hexdigest('SHA256', config['session_secret'], data)
end

def secure_eq?(a, b)
  return false unless a.bytesize == b.bytesize
  diff = 0
  a.bytes.zip(b.bytes) { |x, y| diff |= x ^ y }
  diff.zero?
end

def make_token(payload)
  body = JSON.generate(payload).unpack1('H*')
  "#{body}.#{sign(body)}"
end

def read_token(token)
  return nil unless token&.include?('.')
  body, mac = token.split('.', 2)
  return nil unless secure_eq?(sign(body), mac.to_s)
  JSON.parse([body].pack('H*'))
rescue JSON::ParserError, ArgumentError
  nil
end

def current_email(cgi)
  payload = read_token(Array(cgi.cookies[SESSION_COOKIE]).first)
  return nil unless payload && payload['exp'].to_i > Time.now.to_i
  email = payload['email'].to_s
  allowed?(email) ? email : nil
end

# ---------- Cookie / レスポンス ----------

def script_dir
  File.dirname(ENV.fetch('SCRIPT_NAME', '/'))
end

def script_path
  ENV.fetch('SCRIPT_NAME', '/')
end

# パーマリンクの土台URL（config.json の permalink_base。例: https://kawanoyuki.com/wiki/）
# 未設定なら nil で、その場合は index.cgi?id=<ID> 形式になる
def permalink_base
  b = config['permalink_base'].to_s.strip
  return nil unless b.match?(%r{\A(https?://|/)}i)
  b.end_with?('/') ? b : b + '/'
end

def doc_url(id)
  base = permalink_base
  base ? base + id : "#{script_path}?id=#{id}"
end

# <script> の中へ安全に埋め込める JSON 文字列にする
def js_literal(value)
  JSON.generate([value.to_s])[1..-2].gsub('<') { '\u003c' }.gsub("\u2028") { '\u2028' }
end

def requested_id(cgi)
  id = cgi['id'].to_s
  valid_name?(id) ? id : ''
end

def make_cookie(name, value, expires: nil)
  CGI::Cookie.new('name' => name, 'value' => value, 'path' => script_dir,
                  'secure' => true, 'httponly' => true, 'expires' => expires)
end

def send_json(cgi, obj, status = nil, cookies = nil)
  opts = { 'type' => 'application/json; charset=utf-8' }
  opts['status'] = status if status
  opts['cookie'] = cookies if cookies
  cgi.out(opts) { JSON.generate(obj) }
end

def send_html(cgi, body, status = nil)
  opts = { 'type' => 'text/html; charset=utf-8' }
  opts['status'] = status if status
  cgi.out(opts) { body }
end

def send_redirect(cgi, location, cookies = [])
  cgi.out('status' => 'REDIRECT', 'location' => location, 'cookie' => cookies) { '' }
end

def html_message(title, body)
  <<~HTML
    <!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>#{CGI.escapeHTML(title)}</title></head>
    <body style="font-family:sans-serif;padding:2em"><h2>#{CGI.escapeHTML(title)}</h2>
    <p>#{CGI.escapeHTML(body)}</p><p><a href="?action=login">ログインし直す</a></p></body></html>
  HTML
end

# ---------- Google OAuth ----------

def handle_login(cgi)
  state = SecureRandom.hex(16)
  params = {
    client_id: config['google_client_id'],
    redirect_uri: config['redirect_uri'],
    response_type: 'code',
    scope: 'openid email',
    state: state,
    prompt: 'select_account'
  }
  url = 'https://accounts.google.com/o/oauth2/v2/auth?' + URI.encode_www_form(params)
  cookies = [make_cookie(STATE_COOKIE, state, expires: Time.now + STATE_TTL)]
  rid = requested_id(cgi)
  # ログイン後に、開こうとしていたページへ戻る
  cookies << make_cookie(RETURN_COOKIE, rid, expires: Time.now + STATE_TTL) unless rid.empty?
  send_redirect(cgi, url, cookies)
end

def exchange_code(code)
  res = Net::HTTP.post_form(URI('https://oauth2.googleapis.com/token'),
                            'code' => code,
                            'client_id' => config['google_client_id'],
                            'client_secret' => config['google_client_secret'],
                            'redirect_uri' => config['redirect_uri'],
                            'grant_type' => 'authorization_code')
  raise "token exchange failed (#{res.code})" unless res.is_a?(Net::HTTPSuccess)
  JSON.parse(res.body)['access_token']
end

def fetch_verified_email(access_token)
  uri = URI('https://openidconnect.googleapis.com/v1/userinfo')
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{access_token}"
  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(req) }
  raise "userinfo failed (#{res.code})" unless res.is_a?(Net::HTTPSuccess)
  info = JSON.parse(res.body)
  info['email_verified'] == true ? info['email'].to_s : nil
end

def handle_callback(cgi)
  expected = Array(cgi.cookies[STATE_COOKIE]).first.to_s
  clear_state = make_cookie(STATE_COOKIE, '', expires: Time.at(0))

  if cgi['error'].to_s != '' || cgi['code'].to_s.empty?
    return send_html(cgi, html_message('ログインがキャンセルされました', 'もう一度お試しください。'), 'BAD_REQUEST')
  end
  if expected.empty? || !secure_eq?(expected, cgi['state'].to_s)
    return send_html(cgi, html_message('不正なリクエストです', 'ログインの状態が一致しません。'), 'FORBIDDEN')
  end

  email = fetch_verified_email(exchange_code(cgi['code'].to_s))
  unless allowed?(email)
    return send_html(cgi, html_message('アクセス権がありません', "#{email} は許可されていません。"), 'FORBIDDEN')
  end

  token = make_token('email' => email, 'exp' => Time.now.to_i + SESSION_TTL)
  rid  = Array(cgi.cookies[RETURN_COOKIE]).first.to_s
  dest = valid_name?(rid) ? doc_url(rid) : script_path
  send_redirect(cgi, dest,
                [make_cookie(SESSION_COOKIE, token, expires: Time.now + SESSION_TTL), clear_state,
                 make_cookie(RETURN_COOKIE, '', expires: Time.at(0))])
end

def handle_logout(cgi)
  send_redirect(cgi, ENV.fetch('SCRIPT_NAME', '/'),
                [make_cookie(SESSION_COOKIE, '', expires: Time.at(0))])
end

# ---------- ドキュメント API ----------

def valid_name?(name)
  name.match?(NAME_RE)
end

def doc_path(id)
  File.join(DATA_DIR, "#{id}.html")
end

# 文書タイトルは本文とは別ファイル（<id>.title）に保存する
def title_path(id)
  File.join(DATA_DIR, "#{id}.title")
end

# ファイル名（ID）は自動採番：日時 + ランダム文字列
def new_doc_id
  loop do
    id = Time.now.strftime('%Y%m%d-%H%M%S') + '-' + SecureRandom.hex(3)
    return id unless File.exist?(doc_path(id))
  end
end

def clean_title(raw)
  t = raw.to_s.dup.force_encoding('UTF-8').scrub.gsub(/[[:cntrl:]]+/, ' ').strip
  t = t[0, 100].to_s.strip
  t.empty? ? '無題' : t
end

# タイトル未設定の旧データは、ファイル名をそのままタイトルとして扱う
def read_title(id)
  path = title_path(id)
  File.file?(path) ? clean_title(File.read(path, encoding: 'utf-8')) : id
end

# 許可タグ以外は除去し、属性はすべて捨てる。
# 例外として a[href] は http(s)/mailto/相対/# のみ残す（javascript: 等は不可）。
# ※プロトタイプ用の簡易サニタイザ。公開運用時は専用ライブラリの導入を推奨。
def sanitize(html)
  html = html.gsub(/<!--.*?-->/m, '')
  html.gsub(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/) do
    closing = Regexp.last_match(1)
    tag     = Regexp.last_match(2).downcase
    tag     = TAG_ALIASES.fetch(tag, tag)
    attrs   = Regexp.last_match(3)
    next '' unless ALLOWED_TAGS.include?(tag)
    next "</#{tag}>" unless closing.empty?
    if tag == 'a'
      href = attrs[/\bhref\s*=\s*"([^"]*)"/i, 1] || attrs[/\bhref\s*=\s*'([^']*)'/i, 1]
      if href && href.strip.match?(%r{\A(https?://|mailto:|/|#)}i)
        next %(<a href="#{CGI.escapeHTML(href.strip)}" rel="noopener noreferrer">)
      end
      next '<a>'
    end
    # 子ページ一覧の埋め込み部品（中身はブラウザが表示のたびに作るので、空の div だけを残す）
    if tag == 'div'
      wk = attrs[/\bclass\s*=\s*"\s*(papyru-children(?:-all)?)\s*"/i, 1]
      next %(<div class="#{wk.downcase}">) if wk
    end
    # 字下げ：段落・見出しの class="ind1"〜"ind6" だけを残す（それ以外の属性は捨てる）
    if %w[p h1 h2 h3 div].include?(tag)
      lv = attrs[/\bclass\s*=\s*"(?:[^"]*\s)?ind([1-6])(?:\s[^"]*)?"/i, 1]
      next %(<#{tag} class="ind#{lv}">) if lv
    end
    "<#{tag}>"
  end
end

# ---- 親子関係（<id>.parent に親のIDを保存。無ければ最上位） ----

def parent_path(id)
  File.join(DATA_DIR, "#{id}.parent")
end

def doc_exists?(id)
  valid_name?(id.to_s) && File.file?(doc_path(id))
end

# 親が存在しない・自分自身などの不正な値は「最上位」として扱う
def read_parent(id)
  path = parent_path(id)
  return '' unless File.file?(path)
  pid = File.read(path, encoding: 'utf-8').strip
  (pid != id && doc_exists?(pid)) ? pid : ''
end

def write_parent(id, pid)
  if pid.to_s.empty?
    File.delete(parent_path(id)) if File.file?(parent_path(id))
  else
    File.write(parent_path(id), pid)
    File.chmod(0o600, parent_path(id))
  end
end

# pid が id 自身、または id の子孫なら true（親に指定すると循環してしまう）
def descendant_or_self?(pid, id)
  cur = pid
  200.times do
    return true if cur == id
    cur = read_parent(cur)
    return false if cur.empty?
  end
  true
end

def child_ids(id)
  Dir.glob(File.join(DATA_DIR, '*.html')).map { |f| File.basename(f, '.html') }
     .select { |cid| valid_name?(cid) && read_parent(cid) == id }
end

# POST は同一サイトからのリクエストのみ受け付ける（CSRF対策）。
# ブラウザは POST に Origin を付けるので、ホストが一致しなければ拒否する。
def same_origin?
  origin = ENV['HTTP_ORIGIN'].to_s
  return true if origin.empty?                      # Origin を付けないクライアント（ブラウザ以外）
  host = ENV['HTTP_HOST'].to_s
  host = ENV['SERVER_NAME'].to_s if host.empty?
  return false if host.empty?                       # 確認できないときは拒否する
  u = URI(origin)
  authority = u.port == u.default_port ? u.host.to_s : "#{u.host}:#{u.port}"
  authority.casecmp?(host)
rescue URI::InvalidURIError
  false
end

def post_only(cgi)
  unless cgi.request_method == 'POST'
    send_json(cgi, { ok: false, error: 'POST only' }, 'METHOD_NOT_ALLOWED')
    return false
  end
  unless same_origin?
    send_json(cgi, { ok: false, error: 'forbidden origin' }, 'FORBIDDEN')
    return false
  end
  true
end

# ---- 更新履歴（data/history/<文書ID>/<版ID>.html と .meta） ----
# 保存のたびに版を残す。内容もタイトルも前の版と同じなら、版は増やさない。

HISTORY_DIR   = File.join(DATA_DIR, 'history')
MAX_REVISIONS = 100   # 1ページあたり残す版の数。超えた分は古い版から削除する

def history_dir(id)
  File.join(HISTORY_DIR, id)
end

# 版ID の一覧（古い順）。版ID は日時から作るので、名前順＝時間順になる
def revision_ids(id)
  Dir.glob(File.join(history_dir(id), '*.html'))
     .map { |f| File.basename(f, '.html') }
     .select { |r| valid_name?(r) }
     .sort
end

def read_revision_meta(id, rev)
  JSON.parse(File.read(File.join(history_dir(id), "#{rev}.meta"), encoding: 'utf-8'))
rescue StandardError
  {}
end

def snapshot_revision(id, title, html, by, at: Time.now, note: nil)
  Dir.mkdir(HISTORY_DIR, 0o700) unless Dir.exist?(HISTORY_DIR)
  dir = history_dir(id)
  Dir.mkdir(dir, 0o700) unless Dir.exist?(dir)

  if (last = revision_ids(id).last)
    last_html = File.read(File.join(dir, "#{last}.html"), encoding: 'utf-8')
    return nil if last_html == html && read_revision_meta(id, last)['title'] == title
  end

  rev  = at.strftime('%Y%m%d%H%M%S') + format('%06d', at.usec) + '-' + SecureRandom.hex(2)
  meta = { 'title' => title, 'by' => by.to_s, 'at' => at.strftime('%Y-%m-%d %H:%M:%S'),
           'bytes' => html.bytesize, 'note' => note.to_s }
  File.write(File.join(dir, "#{rev}.html"), html)
  File.write(File.join(dir, "#{rev}.meta"), JSON.generate(meta))
  File.chmod(0o600, File.join(dir, "#{rev}.html"), File.join(dir, "#{rev}.meta"))

  revs = revision_ids(id)
  revs.first([revs.length - MAX_REVISIONS, 0].max).each do |old|
    File.delete(File.join(dir, "#{old}.html")) rescue nil
    File.delete(File.join(dir, "#{old}.meta")) rescue nil
  end
  rev
end

def handle_history(cgi)
  id = cgi['id'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless doc_exists?(id)

  list = revision_ids(id).reverse.map do |rev|
    m = read_revision_meta(id, rev)
    { rev: rev, title: m['title'].to_s, by: m['by'].to_s, at: m['at'].to_s,
      bytes: m['bytes'].to_i, note: m['note'].to_s }
  end
  send_json(cgi, { ok: true, id: id, revisions: list })
end

def handle_revision(cgi)
  id  = cgi['id'].to_s
  rev = cgi['rev'].to_s
  unless doc_exists?(id) && valid_name?(rev) && File.file?(File.join(history_dir(id), "#{rev}.html"))
    return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND')
  end
  m    = read_revision_meta(id, rev)
  html = File.read(File.join(history_dir(id), "#{rev}.html"), encoding: 'utf-8')
  send_json(cgi, { ok: true, id: id, rev: rev, title: m['title'].to_s, by: m['by'].to_s,
                   at: m['at'].to_s, note: m['note'].to_s, html: html })
end

def updated_text(id)
  File.mtime(doc_path(id)).strftime('%Y-%m-%d %H:%M')
end

def handle_list(cgi)
  docs = Dir.glob(File.join(DATA_DIR, '*.html')).map do |f|
    id = File.basename(f, '.html')
    next nil unless valid_name?(id)
    { id: id, title: read_title(id), parent: read_parent(id), mtime: File.mtime(f) }
  end.compact
  docs.sort_by! { |d| -d[:mtime].to_i }
  send_json(cgi, docs.map do |d|
    { id: d[:id], title: d[:title], parent: d[:parent], updated: d[:mtime].strftime('%Y-%m-%d %H:%M') }
  end)
end

def handle_load(cgi)
  id = cgi['id'].to_s
  unless doc_exists?(id)
    return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND')
  end
  html = File.read(doc_path(id), encoding: 'utf-8')
  send_json(cgi, { ok: true, id: id, title: read_title(id), parent: read_parent(id), html: html,
                   updated: updated_text(id), revisions: revision_ids(id).length })
end

# 親ページを変更する（pid が空なら最上位にする）
def handle_move(cgi)
  return unless post_only(cgi)

  id  = cgi['id'].to_s
  pid = cgi['parent'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless doc_exists?(id)
  unless pid.empty? || doc_exists?(pid)
    return send_json(cgi, { ok: false, error: 'parent not found' }, 'BAD_REQUEST')
  end
  if !pid.empty? && descendant_or_self?(pid, id)
    return send_json(cgi, { ok: false, error: 'cannot move into itself or its descendants' }, 'BAD_REQUEST')
  end

  write_parent(id, pid)
  send_json(cgi, { ok: true, id: id, parent: pid })
end

# 文書を削除する。実ファイルは data/trash/ へ移すだけで、完全には消さない。
# 子ページは削除した文書の親（無ければ最上位）へ繰り上げる。
def handle_delete(cgi)
  return unless post_only(cgi)

  id = cgi['id'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless doc_exists?(id)

  grand = read_parent(id)
  children = child_ids(id)
  children.each { |cid| write_parent(cid, grand) }

  trash = File.join(DATA_DIR, 'trash')
  Dir.mkdir(trash, 0o700) unless Dir.exist?(trash)
  stamp = Time.now.strftime('%Y%m%d%H%M%S')
  %w[html title parent].each do |ext|
    src = File.join(DATA_DIR, "#{id}.#{ext}")
    File.rename(src, File.join(trash, "#{stamp}_#{id}.#{ext}")) if File.file?(src)
  end
  # 更新履歴も、文書と一緒にゴミ箱へ移す
  File.rename(history_dir(id), File.join(trash, "#{stamp}_#{id}.history")) if Dir.exist?(history_dir(id))
  send_json(cgi, { ok: true, id: id, promoted: children.size })
end

def handle_save(cgi, email)
  return unless post_only(cgi)

  id    = cgi['id'].to_s.strip
  title = clean_title(cgi['title'])
  # 本文はbase64で受け取る（HTMLタグを含むPOSTがWAF等に弾かれるのを避けるため）。
  # 旧形式（html パラメータ）も受け付ける。
  encoded = cgi['html64'].to_s
  raw  = encoded.empty? ? cgi['html'].to_s : encoded.unpack1('m')
  html = raw.dup.force_encoding('UTF-8').scrub

  # id が空なら新規文書としてファイル名を自動採番、指定があれば上書き保存
  new_doc = id.empty?
  if new_doc
    id = new_doc_id
  elsif !valid_name?(id)
    return send_json(cgi, { ok: false, error: 'invalid id' }, 'BAD_REQUEST')
  end
  return send_json(cgi, { ok: false, error: 'too large' }, 'BAD_REQUEST') if html.bytesize > MAX_BYTES

  clean = sanitize(html)

  # 履歴機能より前からある文書は、上書きする前に元の内容を最初の版として残す
  if !new_doc && File.file?(doc_path(id)) && revision_ids(id).empty?
    snapshot_revision(id, read_title(id), File.read(doc_path(id), encoding: 'utf-8'), '',
                      at: File.mtime(doc_path(id)), note: '履歴機能の導入前の内容')
  end

  File.write(doc_path(id), clean)
  File.write(title_path(id), title)
  File.chmod(0o600, doc_path(id))
  File.chmod(0o600, title_path(id))
  snapshot_revision(id, title, clean, email)

  # 親は新規作成のときだけ指定できる（既存文書の親変更は move を使う）
  pid = cgi['parent'].to_s
  write_parent(id, pid) if new_doc && doc_exists?(pid)
  send_json(cgi, { ok: true, id: id, title: title, parent: read_parent(id),
                   updated: updated_text(id), revisions: revision_ids(id).length })
end

# ---------- 画面 ----------

LOGIN_PAGE = <<~'HTML'
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Papyru - ログイン</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font-family: -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; background: #f2f3f5; }
  .box { background: #fff; padding: 36px 40px; border-radius: 8px; border: 1px solid #ddd; text-align: center; max-width: 360px; }
  h1 { margin: 0 0 8px; font-size: 22px; }
  p { color: #555; }
  a.btn { display: inline-block; margin-top: 16px; padding: 10px 18px; background: #fff; border: 1px solid #777;
          border-radius: 4px; color: #333; text-decoration: none; font-weight: bold; }
</style>
</head>
<body>
<div class="box">
  <h1>Papyru</h1>
  <p>Googleアカウントでログインしてください。</p>
  <a class="btn" href="{{LOGIN_URL}}">Googleでログイン</a>
</div>
</body>
</html>
HTML

PAGE = <<~'HTML'
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Papyru</title>
<style>
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html, body { height: 100%; }
  body { margin: 0; display: flex; flex-direction: column; font-family: -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; background: #f2f3f5; color: #222; }

  header { flex: none; background: #2f3640; color: #fff; padding: 8px 14px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  header .user { font-weight: normal; font-size: 13px; }
  header a { color: #fff; }
  header .menu { font: inherit; background: transparent; color: #fff; border: 1px solid #667; border-radius: 4px; padding: 2px 8px; cursor: pointer; margin-right: 6px; }

  .layout { flex: 1; min-height: 0; display: flex; position: relative; }

  /* サイドバー（文書一覧） */
  #sidebar { flex: none; width: 260px; background: #fff; border-right: 1px solid #ddd; display: flex; flex-direction: column; min-height: 0; }
  body.side-closed #sidebar { display: none; }
  .side-head { padding: 10px; border-bottom: 1px solid #eee; }
  .side-head input { width: 100%; font: inherit; font-size: 14px; padding: 6px 9px; border: 1px solid #bbb; border-radius: 4px; }
  #doclist, #picklist { list-style: none; margin: 0; padding: 0; overflow-y: auto; }
  #doclist { flex: 1; }
  #histlist { list-style: none; margin: 0; padding: 0; overflow-y: auto; }
  #doclist li button, #picklist li button, #histlist li button { display: block; width: 100%; text-align: left; font: inherit; background: transparent; border: 0; border-bottom: 1px solid #f0f0f0; padding: 9px 12px; cursor: pointer; }
  #doclist li button:hover, #picklist li button:hover, #histlist li button:hover { background: #f3f6fd; }
  #doclist li button.active, #histlist li button.active { background: #e3ecff; font-weight: bold; }
  .doc .t { display: block; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .doc .d { display: block; font-size: 11px; color: #888; font-weight: normal; }
  .empty { padding: 14px 12px; color: #888; font-size: 13px; }
  /* 親子ツリー：トグル＋文書ボタンを横に並べ、深さに応じて字下げする */
  #doclist li { display: flex; align-items: stretch; }
  #doclist li .tog, #doclist li .tog-space { flex: none; width: 26px; padding: 0; border: 0; border-bottom: 1px solid #f0f0f0; background: transparent; color: #666; font-size: 11px; }
  #doclist li .tog { cursor: pointer; }
  #doclist li .tog:hover { background: #f3f6fd; }
  #doclist li button.doc { flex: 1; min-width: 0; }
  .doc .p { display: block; font-size: 11px; color: #888; font-weight: normal; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .doc .n { font-size: 11px; color: #888; font-weight: normal; margin-left: 4px; }

  main { flex: 1; min-width: 0; overflow-y: auto; }
  .toolbars { position: sticky; top: 0; z-index: 5; }
  .bar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 8px 14px; background: #fff; border-bottom: 1px solid #ddd; }
  .bar button { font: inherit; font-size: 14px; padding: 5px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }
  .bar button:hover { background: #eee; }
  .bar .primary { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .bar .danger { color: #b3261e; border-color: #e0a8a4; }
  .bar .danger:hover { background: #fdeceb; }
  .bar button:disabled { opacity: .45; cursor: default; }
  .bar .sep { width: 1px; height: 22px; background: #ccc; margin: 0 4px; }
  .crumbs { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 6px; padding: 5px 14px; background: #f7f8fa; border-bottom: 1px solid #ddd; font-size: 13px; color: #555; }
  .crumbs button { font: inherit; border: 0; background: transparent; color: #1a5fd1; cursor: pointer; padding: 0; text-decoration: underline; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .crumbs .cur { color: #222; font-weight: bold; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar .doctitle { font-size: 14px; color: #333; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #status { margin-left: auto; font-size: 13px; color: #555; }
  #status.err { color: #c0392b; }

  #editor { max-width: 860px; margin: 20px auto; min-height: 70vh; background: #fff; padding: 28px 36px; border: 1px solid #ddd; border-radius: 6px; line-height: 1.8; outline: none; }
  #editor:focus { box-shadow: 0 0 0 2px #cfe0ff; }
  #editor h1, #editor h2, #editor h3 { line-height: 1.3; }
  #editor blockquote { margin: 0; padding-left: 12px; border-left: 4px solid #ccc; color: #555; }
  #editor pre, #editor code { background: #f4f4f4; font-family: monospace; }
  #editor h1 { font-size: 1.8em; margin: .8em 0 .4em; }
  #editor h2 { font-size: 1.45em; margin: .8em 0 .4em; }
  #editor h3 { font-size: 1.2em; margin: .8em 0 .4em; }
  #editor .ind1, #histview .ind1 { margin-left: 2em; }  #editor .ind2, #histview .ind2 { margin-left: 4em; }
  #editor .ind3, #histview .ind3 { margin-left: 6em; }  #editor .ind4, #histview .ind4 { margin-left: 8em; }
  #editor .ind5, #histview .ind5 { margin-left: 10em; } #editor .ind6, #histview .ind6 { margin-left: 12em; }
  #editor li > ul, #editor li > ol { margin: 2px 0; }
  .papyru-children, .papyru-children-all { border: 1px solid #d5dbe6; border-left: 4px solid #5b8def; background: #f6f8fc;
    border-radius: 4px; padding: 8px 12px; margin: 12px 0; user-select: none; }
  #histview .papyru-children:empty::before, #histview .papyru-children-all:empty::before {
    content: '［子ページ一覧を埋め込み］'; color: #667; font-size: 13px; }
  .pc-head { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: bold; color: #47536b; margin-bottom: 4px; }
  .pc-ctl { margin-left: auto; display: flex; gap: 6px; align-items: center; }
  .pc-ctl select, .pc-ctl button { font: inherit; font-size: 12px; padding: 1px 6px; }
  .pc-row { padding: 2px 0; line-height: 1.6; }
  .pc-item { color: #1a5fd1; cursor: pointer; border-radius: 3px; }
  .pc-item::before { content: '▸ '; color: #8a94a8; }
  .pc-item:hover, .pc-item:focus-visible { text-decoration: underline; outline: none; }
  .pc-empty { color: #888; font-size: 13px; }
  #editor a { color: #1a5fd1; text-decoration: underline; cursor: pointer; }
  #editor table, #histview table { border-collapse: collapse; margin: 12px 0; max-width: 100%; }
  #editor th, #editor td, #histview th, #histview td { border: 1px solid #bbb; padding: 6px 10px; min-width: 60px; vertical-align: top; line-height: 1.6; }
  #editor th, #histview th { background: #f1f3f6; text-align: left; }
  #editor s, #histview s { text-decoration: line-through; color: #777; }
  #histview h1 { font-size: 1.8em; } #histview h2 { font-size: 1.45em; } #histview h3 { font-size: 1.2em; }
  #editor a[href^="#doc="] { background: #eaf2ff; border-radius: 3px; padding: 0 2px; text-decoration: none; border-bottom: 1px solid #1a5fd1; }

  /* 表示モード／編集モード */
  body.mode-view .edit-only { display: none !important; }
  body.mode-edit .view-only { display: none !important; }
  body.mode-view #editor { cursor: default; }
  body.mode-view #editor:focus { box-shadow: none; }
  body.mode-view #editor a { cursor: pointer; }
  body.mode-edit #editor { border-color: #f0c36d; }
  .badge { display: inline-block; font-size: 11px; padding: 1px 8px; border-radius: 10px; margin-left: 6px; background: #e3ecff; color: #1a5fd1; vertical-align: 1px; }
  body.mode-edit .badge { background: #fff1d6; color: #9a5b00; }
  .meta { color: #777; }

  /* 更新履歴ダイアログ */
  #histdlg { position: fixed; inset: 0; z-index: 40; background: rgba(0,0,0,.35); display: flex; align-items: center; justify-content: center; padding: 16px; }
  .hist-box { background: #fff; width: 900px; max-width: 100%; height: 82vh; border-radius: 8px; display: flex; flex-direction: column; padding: 14px; gap: 10px; }
  .hist-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .hist-head .t { font-weight: bold; }
  .hist-body { flex: 1; min-height: 0; display: flex; gap: 12px; }
  #histlist { flex: none; width: 270px; border: 1px solid #eee; border-radius: 4px; }
  .hist-pane { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; gap: 6px; }
  #histinfo { font-size: 13px; color: #555; }
  #histview { flex: 1; min-height: 0; overflow-y: auto; border: 1px solid #eee; border-radius: 4px; padding: 14px 20px; line-height: 1.8; }
  #histview h1, #histview h2, #histview h3 { line-height: 1.3; }
  #histview blockquote { margin: 0; padding-left: 12px; border-left: 4px solid #ccc; color: #555; }
  #histview pre, #histview code { background: #f4f4f4; font-family: monospace; }
  #histview a { color: #1a5fd1; text-decoration: underline; cursor: default; }
  .hist-tabs { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .hist-tabs button.tab { font: inherit; font-size: 13px; padding: 3px 12px; border: 1px solid #bbb; border-radius: 14px; background: #fafafa; cursor: pointer; }
  .hist-tabs button.tab.on { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .hist-tabs select { font: inherit; font-size: 13px; padding: 2px 6px; }
  #histdiff { flex: 1; min-height: 0; overflow: auto; border: 1px solid #eee; border-radius: 4px; padding: 8px 0; font-size: 14px; }
  #diffsum { font-size: 13px; color: #555; padding: 2px 14px 8px; }
  .dl { position: relative; padding: 2px 12px 2px 34px; line-height: 1.6; white-space: pre-wrap; word-break: break-word; border-left: 3px solid transparent; color: #666; }
  .dl::before { position: absolute; left: 12px; width: 14px; text-align: center; font-weight: bold; }
  .dl.add { background: #e8f7ec; border-left-color: #2e9d4f; color: #1d1d1d; }
  .dl.add::before { content: '+'; color: #2e9d4f; }
  .dl.del { background: #fdecec; border-left-color: #d64545; color: #1d1d1d; }
  .dl.del::before { content: '−'; color: #d64545; }
  .dl.add .chg { background: #a8e6b8; border-radius: 2px; }
  .dl.del .chg { background: #f6b5b5; border-radius: 2px; }
  .dl.skip { text-align: center; color: #999; font-size: 12px; padding: 4px; }
  .hist-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .hist-box button.act { font: inherit; font-size: 14px; padding: 5px 12px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }
  .hist-box button.act.primary { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .hist-box button.act:disabled { opacity: .45; cursor: default; }
  .doc .cur-tag { font-size: 10px; background: #2f6fed; color: #fff; border-radius: 8px; padding: 0 6px; margin-left: 6px; font-weight: normal; vertical-align: 1px; }

  /* リンク操作ポップオーバー */
  #linkpop { position: fixed; z-index: 30; display: flex; align-items: center; gap: 8px; max-width: 92vw; background: #2f3640; color: #fff; padding: 6px 8px; border-radius: 6px; font-size: 13px; box-shadow: 0 2px 8px rgba(0,0,0,.25); }
  #linkpop #poplabel { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #linkpop button { font: inherit; font-size: 12px; background: #fff; color: #222; border: 0; border-radius: 4px; padding: 3px 8px; cursor: pointer; }
  #linkpop button:disabled { opacity: .5; cursor: default; }

  /* ページリンク選択ダイアログ */
  #picker { position: fixed; inset: 0; z-index: 40; background: rgba(0,0,0,.35); display: flex; align-items: center; justify-content: center; padding: 16px; }
  .picker-box { background: #fff; width: 420px; max-width: 100%; max-height: 80vh; border-radius: 8px; display: flex; flex-direction: column; padding: 14px; gap: 10px; }
  .picker-title { font-weight: bold; }
  .picker-box input { font: inherit; font-size: 14px; padding: 6px 9px; border: 1px solid #bbb; border-radius: 4px; }
  #picklist { border: 1px solid #eee; border-radius: 4px; min-height: 80px; }
  .picker-box > button { align-self: flex-end; font: inherit; padding: 5px 12px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }

  @media (max-width: 720px) {
    .hist-body { flex-direction: column; }
    #histlist { width: auto; max-height: 28%; flex: none; }
    #sidebar { position: absolute; z-index: 20; top: 0; bottom: 0; left: 0; box-shadow: 2px 0 10px rgba(0,0,0,.2); }
    #editor { margin: 10px; padding: 16px; }
  }
</style>
</head>
<body>
<header>
  <span><button id="menu" class="menu" title="文書一覧の表示／非表示">☰</button>Papyru（プロトタイプ）</span>
  <span class="user">{{EMAIL}} ・ <a href="{{SCRIPT_HTML}}?action=logout">ログアウト</a></span>
</header>

<div class="layout">
  <aside id="sidebar">
    <div class="side-head"><input id="filter" type="search" placeholder="タイトルで絞り込み"></div>
    <ul id="doclist"></ul>
  </aside>

  <main id="main">
    <div class="toolbars">
      <div class="bar edit-only" id="fmtbar">
        <button data-cmd="undo" title="元に戻す">↶</button>
        <button data-cmd="redo" title="やり直し">↷</button>
        <span class="sep"></span>
        <button data-cmd="formatBlock" data-arg="h1" title="見出し1（大）">見出し1</button>
        <button data-cmd="formatBlock" data-arg="h2" title="見出し2（中）">見出し2</button>
        <button data-cmd="formatBlock" data-arg="h3" title="見出し3（小）">見出し3</button>
        <button data-cmd="formatBlock" data-arg="p">本文</button>
        <button data-cmd="formatBlock" data-arg="blockquote">引用</button>
        <span class="sep"></span>
        <button data-cmd="bold"><b>B</b></button>
        <button data-cmd="italic"><i>I</i></button>
        <button data-cmd="underline"><u>U</u></button>
        <button data-cmd="strikeThrough"><s>S</s></button>
        <span class="sep"></span>
        <button data-cmd="insertUnorderedList">• リスト</button>
        <button data-cmd="insertOrderedList">1. リスト</button>
        <span class="sep"></span>
        <button id="pagelink" title="選択した文字を、保存済みのページへのリンクにする">ページリンク</button>
        <button data-cmd="createLink" title="選択した文字を、URLへのリンクにする">URLリンク</button>
        <button id="unlinkBtn" title="選択範囲（またはカーソル位置）のリンクを解除">リンク解除</button>
        <span class="sep"></span>
        <button data-cmd="insertHorizontalRule">罫線</button>
        <button id="outdentBtn" title="字下げを減らす（Shift+Tab）">⇤ 戻す</button>
        <button id="indentBtn" title="字下げを増やす（Tab）">⇥ 字下げ</button>
        <span class="sep"></span>
        <button id="tblInsert" title="カーソル位置に3行×3列の表を挿入">表</button>
        <button data-tbl="rowAdd" title="カーソルのある行の下に行を追加">行＋</button>
        <button data-tbl="rowDel" title="カーソルのある行を削除">行－</button>
        <button data-tbl="colAdd" title="カーソルのある列の右に列を追加">列＋</button>
        <button data-tbl="colDel" title="カーソルのある列を削除">列－</button>
        <button data-tbl="tblDel" title="カーソルのある表を削除">表削除</button>
        <span class="sep"></span>
        <button id="childrenBtn" title="このページの子ページ一覧を、カーソルのある段落の下に埋め込む">子ページ一覧</button>
        <span class="sep"></span>
        <button data-cmd="removeFormat">書式クリア</button>
      </div>

      <div class="bar">
        <span class="doctitle">タイトル：<strong id="doctitle">無題</strong><span id="modebadge" class="badge">編集中</span></span>
        <button id="editBtn" class="primary view-only" title="このページを編集する">編集</button>
        <button id="save" class="primary edit-only">保存 (Ctrl+S)</button>
        <button id="saveView" class="edit-only" title="保存して、閲覧モードに戻る">保存して閲覧</button>
        <button id="cancelEdit" class="edit-only" title="変更を破棄して、閲覧モードに戻る">破棄して閲覧</button>
        <span class="sep"></span>
        <button id="new">新規</button>
        <button id="addchild" class="view-only" title="開いているページの下に、新しい子ページを作る">子ページを作成</button>
        <button id="moveBtn" title="開いているページの親ページを変更する">親を変更</button>
        <button id="histBtn" title="このページの更新履歴を見る">履歴</button>
        <button id="copyLink" title="このページ固有のリンク（パーマリンク）をコピー">🔗 リンクをコピー</button>
        <button id="delBtn" class="danger view-only" title="開いているページを削除する">削除</button>
        <span id="status"></span>
      </div>
      <div id="crumbs" class="crumbs" hidden></div>
      <div id="docmeta" class="crumbs meta" hidden></div>
    </div>

    <div id="editor" spellcheck="false"><p>ここに入力してください。</p></div>
  </main>
</div>

<div id="linkpop" hidden>
  <span id="poplabel"></span>
  <button id="popopen">開く</button>
  <button id="popremove">解除</button>
</div>

<div id="histdlg" hidden>
  <div class="hist-box" role="dialog" aria-label="更新履歴">
    <div class="hist-head">
      <span class="t" id="histtitle">更新履歴</span>
      <button class="act" id="histclose">閉じる</button>
    </div>
    <div class="hist-body">
      <ul id="histlist"></ul>
      <div class="hist-pane">
        <div id="histinfo"></div>
        <div class="hist-tabs">
          <button class="tab on" id="tabView">内容</button>
          <button class="tab" id="tabDiff">差分</button>
          <select id="diffbase" aria-label="比較対象" hidden>
            <option value="prev">1つ前の版 → この版</option>
            <option value="latest">この版 → 現在の版</option>
          </select>
        </div>
        <div id="histview"></div>
        <div id="histdiff" hidden></div>
        <div class="hist-actions">
          <button class="act primary" id="histrestore" disabled>この版を編集用に読み込む</button>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="picker" hidden>
  <div class="picker-box" role="dialog" aria-label="リンク先のページを選択">
    <div class="picker-title" id="pickertitle">リンク先のページを選択</div>
    <input id="pickfilter" type="search" placeholder="タイトルで絞り込み（Enterで先頭を選択）">
    <ul id="picklist"></ul>
    <button id="pickcancel">キャンセル</button>
  </div>
</div>

<script>
(() => {
  const $ = id => document.getElementById(id);
  const ep = {{SCRIPT_JS}};          // index.cgi のパス（API の送信先）
  const PERMA_BASE = {{PERMA_JS}};   // パーマリンクの土台URL（空なら ?id= 形式）
  const INITIAL_ID = {{ID_JS}};      // URL で指定されたページID
  const NAME_RE = /^[A-Za-z0-9_-]{1,50}$/;
  const editor = $('editor');
  const main = $('main');
  const titleEl = $('doctitle');
  const statusEl = $('status');
  const listEl = $('doclist');
  const filterEl = $('filter');
  const pop = $('linkpop');
  const picker = $('picker');
  const pickFilter = $('pickfilter');
  const pickList = $('picklist');

  let currentId = '';   // 開いている文書のID（空なら未保存の新規文書）
  let dirty = false;    // 未保存の変更があるか
  let saving = false;
  let docs = [];        // 保存済み文書の一覧キャッシュ [{id, title, parent, updated}]
  let savedRange = null;
  let popAnchor = null;
  let currentParent = '';   // 開いている文書（新規なら作成予定）の親ID。空なら最上位
  let pickerMode = 'link';  // 'link' = ページリンクの選択 / 'parent' = 親ページの選択
  let mode = 'edit';        // 'view' = 閲覧モード（読み取り専用） / 'edit' = 編集モード
  let docMeta = null;       // 開いている文書の {updated, revisions}

  // サイドバーで折りたたんでいる文書のID（この端末のブラウザにだけ記憶する）
  const COLLAPSE_KEY = 'papyru_collapsed';
  let collapsed = new Set();
  try { collapsed = new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || '[]')); } catch (_) {}
  const saveCollapsed = () => {
    try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify([...collapsed])); } catch (_) {}
  };

  const msg = (text, err = false) => {
    statusEl.textContent = text;
    statusEl.className = err ? 'err' : '';
  };

  // ---------- 親子ツリー ----------

  let byId = new Map();   // id -> 文書
  let kids = new Map();   // 親ID（最上位は ''）-> 子の配列（タイトル順）
  const byTitle = (a, b) => a.title.localeCompare(b.title, 'ja', { numeric: true });
  const titleOf = id => (byId.get(id) || {}).title;

  function indexDocs() {
    byId = new Map(docs.map(d => [d.id, d]));
    for (const d of docs) {
      d.parent = (d.parent && d.parent !== d.id && byId.has(d.parent)) ? d.parent : '';
    }
    // 親をたどっても最上位に着かない（循環）場合は、一覧から消えないよう最上位に戻す
    for (const d of docs) {
      let c = d.parent, n = 0;
      while (c && n++ <= docs.length) c = byId.get(c).parent;
      if (c) d.parent = '';
    }
    kids = new Map();
    for (const d of docs) {
      if (!kids.has(d.parent)) kids.set(d.parent, []);
      kids.get(d.parent).push(d);
    }
    for (const arr of kids.values()) arr.sort(byTitle);
  }

  // 最上位から親までの文書の配列（自分自身は含まない）
  function ancestorsOf(id) {
    const out = [];
    let c = (byId.get(id) || {}).parent;
    while (c && out.length < 100) {
      const d = byId.get(c);
      if (!d) break;
      out.unshift(d);
      c = d.parent;
    }
    return out;
  }

  function descendantIds(id) {
    const set = new Set();
    const stack = [id];
    while (stack.length) {
      for (const k of kids.get(stack.pop()) || []) {
        if (!set.has(k.id)) { set.add(k.id); stack.push(k.id); }
      }
    }
    return set;
  }

  const pathText = id => ancestorsOf(id).map(d => d.title).join(' › ');

  // ---------- 通信ヘルパー ----------

  // サーバーがJSON以外（エラーページ等）を返した場合に、原因が分かる内容を表示する
  async function readJson(r) {
    const text = await r.text();
    try {
      return JSON.parse(text);
    } catch (_) {
      const snippet = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
      throw new Error(`サーバーの応答が不正です（HTTP ${r.status}）${snippet ? '：' + snippet : '（本文なし）'}`);
    }
  }

  // UTF-8 の文字列を base64 に変換
  function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  // ---------- ページリンク ----------

  // ページリンクは href="#doc=<文書ID>" の形で保存する
  function docIdOf(a) {
    const h = a.getAttribute('href') || '';
    const base = location.origin + location.pathname;
    const frag = h.startsWith('#doc=') ? h : (h.startsWith(base + '#doc=') ? h.slice(base.length) : '');
    const m = frag.match(/^#doc=([A-Za-z0-9_-]+)$/);
    return m ? m[1] : null;
  }

  // ブラウザによってhrefが絶対URLに変換されることがあるため、保存前に #doc=ID に揃える
  function serializeEditor() {
    const clone = editor.cloneNode(true);
    // 子ページ一覧は、中身を捨てて目印の空 div だけを保存する
    clone.querySelectorAll(WIDGET_SEL).forEach(w => {
      const d = document.createElement('div');
      d.className = w.classList.contains('papyru-children-all') ? 'papyru-children-all' : 'papyru-children';
      w.replaceWith(d);
    });
    clone.querySelectorAll('a').forEach(a => {
      const id = docIdOf(a);
      if (id) a.setAttribute('href', '#doc=' + id);
    });
    return clone.innerHTML;
  }

  function removeAnchor(a) {
    const parent = a.parentNode;
    while (a.firstChild) parent.insertBefore(a.firstChild, a);
    parent.removeChild(a);
    parent.normalize();
  }

  function anchorAtCaret() {
    const sel = window.getSelection();
    if (!sel.rangeCount || !sel.anchorNode || !editor.contains(sel.anchorNode)) return null;
    let n = sel.anchorNode;
    if (n.nodeType === 3) n = n.parentNode;
    const a = n.closest ? n.closest('a') : null;
    return a && editor.contains(a) ? a : null;
  }

  function openLink(a) {
    const id = docIdOf(a);
    if (id) {
      if (!titleOf(id)) return msg('リンク先のページが見つかりません', true);
      return load(id);
    }
    const href = a.getAttribute('href') || '';
    if (/^(https?:\/\/|mailto:)/i.test(href)) window.open(href, '_blank', 'noopener');
  }

  // カーソルがリンク内にあるとき、「開く／解除」の小さなメニューを表示する
  function updatePop() {
    if (mode !== 'edit') { pop.hidden = true; popAnchor = null; return; }   // 閲覧モードでは出さない
    const a = anchorAtCaret();
    popAnchor = a;
    if (!a) { pop.hidden = true; return; }
    const id = docIdOf(a);
    const label = $('poplabel');
    const openBtn = $('popopen');
    if (id) {
      const t = titleOf(id);
      label.textContent = t ? `ページ：${t}` : 'リンク先のページが見つかりません';
      openBtn.disabled = !t;
    } else {
      label.textContent = a.getAttribute('href') || '';
      openBtn.disabled = false;
    }
    pop.hidden = false;
    const rect = a.getBoundingClientRect();
    const left = Math.min(Math.max(8, rect.left), Math.max(8, window.innerWidth - pop.offsetWidth - 8));
    let top = rect.bottom + 6;
    if (top + pop.offsetHeight > window.innerHeight) top = Math.max(8, rect.top - pop.offsetHeight - 6);
    pop.style.left = left + 'px';
    pop.style.top = top + 'px';
  }

  function showPicker(mode, title) {
    pickerMode = mode;
    $('pickertitle').textContent = title;
    pickFilter.value = '';
    renderPicker();
    picker.hidden = false;
    pickFilter.focus();
  }

  function openPicker() {
    const sel = window.getSelection();
    if (!sel.rangeCount || sel.isCollapsed || !editor.contains(sel.anchorNode) || !editor.contains(sel.focusNode)) {
      return msg('リンクにする文字を、先に選択してください', true);
    }
    savedRange = sel.getRangeAt(0).cloneRange();
    showPicker('link', 'リンク先のページを選択');
  }

  function openParentPicker() {
    showPicker('parent', '親ページを選択');
  }

  function closePicker() {
    picker.hidden = true;
  }

  function renderPicker() {
    const q = pickFilter.value.trim().toLowerCase();
    let items;
    if (pickerMode === 'parent') {
      // 自分自身と、自分の子孫は親にできない（循環してしまうため）
      const banned = currentId ? descendantIds(currentId) : new Set();
      if (currentId) banned.add(currentId);
      items = docs.filter(d => !banned.has(d.id) && d.title.toLowerCase().includes(q)).sort(byTitle);
    } else {
      items = docs.filter(d => d.title.toLowerCase().includes(q));
    }
    pickList.replaceChildren();
    const addRow = (id, title, sub, isTop) => {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.className = 'doc';
      b.dataset.id = id;
      if (isTop) b.dataset.top = '1';
      b.innerHTML = '<span class="t"></span><span class="d"></span>';
      b.querySelector('.t').textContent = title;
      b.querySelector('.d').textContent = sub;
      li.append(b);
      pickList.append(li);
    };
    if (pickerMode === 'parent' && !q) {
      addRow('', '（最上位にする）', currentParent ? '親ページなし' : '現在の位置', true);
    }
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = docs.length ? '該当するページがありません' : '保存済みのページがありません（先に保存してください）';
      pickList.append(li);
      return;
    }
    for (const d of items) addRow(d.id, d.title, d.parent ? pathText(d.id) : d.updated, false);
  }

  function applyChoice(id) {
    if (pickerMode === 'parent') applyParent(id);
    else applyPageLink(id);
  }

  // 親ページを変更する。保存済みの文書はサーバーに反映し、未保存の新規文書は保存時に反映する
  async function applyParent(pid) {
    closePicker();
    if (pid === currentParent) return;
    if (!currentId) {
      currentParent = pid;
      updateCrumbs();
      return msg(pid ? `親ページを「${titleOf(pid)}」にしました（保存すると反映されます）` : '最上位にしました');
    }
    try {
      const r = await fetch(ep + '?action=move', {
        method: 'POST',
        body: new URLSearchParams({ id: currentId, parent: pid }),
      });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      currentParent = j.parent || '';
      await refresh();
      revealCurrent();
      msg(pid ? `親ページを「${titleOf(pid)}」に変更しました` : '最上位に移動しました');
    } catch (e) {
      msg('親ページの変更に失敗しました：' + e.message, true);
    }
  }

  function applyPageLink(id) {
    closePicker();
    editor.focus();
    const sel = window.getSelection();
    sel.removeAllRanges();
    if (savedRange) sel.addRange(savedRange);
    document.execCommand('createLink', false, '#doc=' + id);
    editor.querySelectorAll('a').forEach(a => {
      const docId = docIdOf(a);
      if (docId) a.setAttribute('href', '#doc=' + docId);
    });
    dirty = true;
    msg(`ページリンクを付けました：${titleOf(id) || id}`);
    updatePop();
  }

  function unlinkSelection() {
    const sel = window.getSelection();
    if (!sel.rangeCount || !sel.anchorNode || !editor.contains(sel.anchorNode)) {
      return msg('リンクを解除したい場所を、エディタ内で選択してください', true);
    }
    const targets = new Set();
    const own = anchorAtCaret();
    if (own) targets.add(own);
    editor.querySelectorAll('a').forEach(a => {
      if (sel.containsNode(a, true)) targets.add(a);
    });
    if (!targets.size) return msg('選択範囲にリンクがありません', true);
    targets.forEach(removeAnchor);
    dirty = true;
    msg('リンクを解除しました');
    updatePop();
  }

  // ---------- サイドバー（文書一覧） ----------

  function makeRow(d, depth, flat) {
    const li = document.createElement('li');
    const childCount = (kids.get(d.id) || []).length;
    if (!flat) {
      li.style.paddingLeft = (depth * 14) + 'px';
      if (childCount) {
        const t = document.createElement('button');
        t.className = 'tog';
        t.dataset.toggle = d.id;
        const closed = collapsed.has(d.id);
        t.textContent = closed ? '▶' : '▼';
        t.title = closed ? '子ページを表示' : '子ページを隠す';
        li.append(t);
      } else {
        const sp = document.createElement('span');
        sp.className = 'tog-space';
        li.append(sp);
      }
    }
    const b = document.createElement('button');
    b.className = 'doc' + (d.id === currentId ? ' active' : '');
    b.dataset.id = d.id;
    b.innerHTML = '<span class="t"></span><span class="d"></span>';
    b.querySelector('.t').textContent = d.title;
    b.querySelector('.d').textContent = flat && d.parent
      ? pathText(d.id)                                              // 絞り込み中は親の名前を添える
      : d.updated + (childCount ? ` ・ 子ページ ${childCount}件` : '');
    li.append(b);
    return li;
  }

  function renderList() {
    const q = filterEl.value.trim().toLowerCase();
    listEl.replaceChildren();
    const empty = text => {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = text;
      listEl.append(li);
    };
    if (q) {   // 絞り込み中は階層を使わず、一致した文書を一覧にする
      const items = docs.filter(d => d.title.toLowerCase().includes(q)).sort(byTitle);
      if (!items.length) return empty('該当する文書がありません');
      for (const d of items) listEl.append(makeRow(d, 0, true));
      return;
    }
    if (!docs.length) return empty('保存済みの文書はありません');
    const walk = (parent, depth) => {
      for (const d of kids.get(parent) || []) {
        listEl.append(makeRow(d, depth, false));
        if ((kids.get(d.id) || []).length && !collapsed.has(d.id)) walk(d.id, depth + 1);
      }
    };
    walk('', 0);
  }

  // 開いている文書が隠れないよう、その親（祖先）を展開してから一覧を描き直す
  function revealCurrent() {
    let changed = false;
    if (currentParent) {
      const chain = [...ancestorsOf(currentParent).map(d => d.id), currentParent];
      for (const id of chain) if (collapsed.delete(id)) changed = true;
    }
    if (changed) saveCollapsed();
    renderList();
  }

  async function refresh() {
    const r = await fetch(ep + '?action=list', { cache: 'no-store' });
    const list = await readJson(r);
    if (!r.ok) throw new Error(list.error || r.status);
    docs = list;
    indexDocs();
    renderList();
    updateCrumbs();
    renderWidgets();
  }

  // ---------- パンくず（親 › 子 › 現在のページ） ----------

  function updateCrumbs() {
    const box = $('crumbs');
    if (!currentParent || !byId.has(currentParent)) { box.hidden = true; return; }
    box.replaceChildren();
    const chain = [...ancestorsOf(currentParent), byId.get(currentParent)];
    for (const d of chain) {
      const b = document.createElement('button');
      b.dataset.id = d.id;
      b.textContent = d.title;
      box.append(b, document.createTextNode('›'));
    }
    const cur = document.createElement('span');
    cur.className = 'cur';
    cur.textContent = deriveTitle() + (currentId ? '' : '（未保存）');
    box.append(cur);
    box.hidden = false;
  }

  function updateButtons() {
    $('addchild').disabled = !currentId;   // 子ページは、保存済みのページの下にだけ作れる
    $('delBtn').disabled = !currentId;
    $('histBtn').disabled = !currentId;    // 履歴は、保存済みのページにだけある
    $('copyLink').disabled = !currentId;   // IDは、保存したページにだけ付く
    $('cancelEdit').disabled = !currentId; // 未保存の新規ページには、戻る先がない
  }

  // 最終更新と履歴の件数を表示する（保存済みのページのみ）
  function setMeta(m) {
    docMeta = m || null;
    const box = $('docmeta');
    if (!docMeta || !currentId) { box.hidden = true; return; }
    box.textContent = `最終更新 ${docMeta.updated} ・ 履歴 ${docMeta.revisions}件 ・ ID ${currentId}`;
    box.hidden = false;
  }

  // ---------- 表示モード／編集モード ----------

  function setMode(m) {
    mode = m;
    document.body.classList.toggle('mode-view', m === 'view');
    document.body.classList.toggle('mode-edit', m === 'edit');
    editor.contentEditable = m === 'edit' ? 'true' : 'false';
    $('modebadge').textContent = m === 'edit' ? '編集中' : '閲覧中';
    pop.hidden = true;
    popAnchor = null;
    updateButtons();
    renderWidgets();
    if (m === 'edit') editor.focus();
  }

  const isBlank = () => !(editor.innerText || '').trim() && !editor.querySelector('hr, ' + WIDGET_SEL);

  // ---------- 保存・読み込み ----------

  // タイトルは本文の最初の空でない行から自動で決める（最大60文字）
  function deriveTitle() {
    const src = Array.from(editor.childNodes).map(n =>
      n.nodeType === 3 ? n.textContent : (n.nodeType === 1 && !n.matches(WIDGET_SEL) ? n.innerText : '')).join('\n');
    const line = src.split('\n').map(s => s.trim()).find(s => s) || '';
    return Array.from(line).slice(0, 60).join('') || '無題';
  }

  function updateTitleLabel() {
    renderWidgets();
    const t = deriveTitle();
    titleEl.textContent = t;
    document.title = t + ' - Papyru';   // タブ・ブックマーク・履歴に、ページのタイトルを出す
    updateCrumbs();
    updateButtons();
  }

  // 保存に成功したら true を返す
  async function save() {
    if (saving) return false;
    if (!currentId && isBlank()) {
      msg('本文が空のページは保存できません', true);
      return false;
    }
    saving = true;
    try {
      const r = await fetch(ep + '?action=save', {
        method: 'POST',
        body: new URLSearchParams({
          id: currentId,                 // 空なら新規（ファイル名はサーバーが自動採番）
          parent: currentParent,         // 親は新規作成のときだけ使われる
          title: deriveTitle(),
          html64: toBase64(serializeEditor()),
        }),
      });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      currentId = j.id;
      currentParent = j.parent || '';
      dirty = false;
      syncUrl(j.id, 'replace');
      msg(j.revisions > 1 ? `保存しました：${j.title}（履歴 ${j.revisions}件）` : `保存しました：${j.title}`);
      await refresh();
      revealCurrent();
      updateTitleLabel();
      setMeta({ updated: j.updated, revisions: j.revisions });
      updatePop();
      return true;
    } catch (e) {
      msg('保存に失敗しました：' + e.message, true);
      return false;
    } finally {
      saving = false;
    }
  }

  // 文書を開く。開いたあとは必ず閲覧モードになる。opts.force なら同じ文書でも読み直す
  // ---- パーマリンク ----
  const urlFor = id => PERMA_BASE ? PERMA_BASE + id : ep + '?id=' + id;
  const absUrl = id => new URL(id ? urlFor(id) : (PERMA_BASE || ep), location.href).href;

  function idFromLocation() {
    const q = new URLSearchParams(location.search).get('id');
    if (q && NAME_RE.test(q)) return q;
    if (PERMA_BASE) {
      const bp = new URL(PERMA_BASE, location.href).pathname;
      if (location.pathname.startsWith(bp) && NAME_RE.test(location.pathname.slice(bp.length))) {
        return location.pathname.slice(bp.length);
      }
    }
    return '';
  }

  // アドレスバーを、開いているページのパーマリンクにそろえる（how: 'push' | 'replace'）
  function syncUrl(id, how) {
    try {
      const target = absUrl(id);
      if (new URL(target).origin !== location.origin || target === location.href) return;
      history[how === 'replace' ? 'replaceState' : 'pushState']({ id }, '', target);
    } catch (e) { /* アドレスバーを変えられなくても動作に影響しない */ }
  }

  async function copyLink() {
    if (!currentId) return;
    const url = absUrl(currentId);
    try {
      await navigator.clipboard.writeText(url);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = url;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.append(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e2) { /* 下で案内 */ }
      ta.remove();
      if (!ok) { prompt('このリンクをコピーしてください', url); return; }
    }
    msg('このページのリンクをコピーしました：' + url);
  }

  // 文書を開く。成功したら true。opts.force: 同じ文書でも読み直す / opts.url: 'push'(既定)|'replace'|'none'
  async function load(id, opts = {}) {
    if (!id) return false;
    if (!opts.force && id === currentId && !dirty) return true;
    if (dirty && !confirm('未保存の変更があります。破棄して開きますか？')) return false;
    try {
      const r = await fetch(ep + '?action=load&id=' + encodeURIComponent(id), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      editor.innerHTML = j.html;
      currentId = j.id;
      currentParent = j.parent || '';
      dirty = false;
      setMode('view');
      setMeta({ updated: j.updated, revisions: j.revisions });
      updateTitleLabel();
      revealCurrent();
      updatePop();
      main.scrollTop = 0;
      msg(`開きました：${j.title}`);
      if (window.innerWidth <= 720) document.body.classList.add('side-closed');
      if (opts.url !== 'none') syncUrl(j.id, opts.url || 'push');
      return true;
    } catch (e) {
      msg(e.message === 'not found' ? '指定されたページは見つかりません（削除された可能性があります）'
                                    : '読み込みに失敗しました：' + e.message, true);
      return false;
    }
  }

  // 保存して閲覧モードに戻る（変更がなければ保存せずに戻る）
  async function saveAndView() {
    if ((dirty || !currentId) && !(await save())) return;
    setMode('view');
    msg(`閲覧モードにしました：${titleOf(currentId) || deriveTitle()}`);
  }

  // 変更を破棄して閲覧モードに戻る（サーバーに保存されている内容を読み直す）
  async function cancelEdit() {
    if (!currentId) return;
    if (dirty && !confirm('未保存の変更を破棄して、閲覧モードに戻りますか？')) return;
    dirty = false;
    await load(currentId, { force: true });
  }

  // 空の新規文書を開く。parentId を渡すと、その子ページとして作成する
  function startNew(parentId, opts = {}) {
    editor.innerHTML = '<p><br></p>';
    currentId = '';
    currentParent = parentId;
    dirty = false;
    setMeta(null);
    setMode('edit');
    updateTitleLabel();
    revealCurrent();
    updatePop();
    msg(parentId ? `「${titleOf(parentId)}」の子ページを作成します（1行目がタイトルになります）` : '新規ドキュメント');
    if (!opts.noUrl) syncUrl('', 'push');
    editor.focus();
  }

  function newDoc() {
    if (dirty && !confirm('未保存の変更があります。破棄して新規作成しますか？')) return;
    startNew('');
  }

  function addChild() {
    if (!currentId) return msg('先に保存してから、子ページを作成してください', true);
    if (dirty && !confirm('未保存の変更があります。破棄して子ページを作成しますか？')) return;
    startNew(currentId);
  }

  async function deleteDoc() {
    if (!currentId) return;
    const id = currentId;
    const title = titleOf(id) || deriveTitle();
    const n = (kids.get(id) || []).length;
    const text = `「${title}」を削除しますか？`
      + (n ? `\n\n子ページ ${n} 件は、ひとつ上の階層に移動します。` : '')
      + '\n\nこのページへのリンクは「見つかりません」になります。';
    if (!confirm(text)) return;
    try {
      const r = await fetch(ep + '?action=delete', {
        method: 'POST',
        body: new URLSearchParams({ id }),
      });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      const back = currentParent;   // 削除後は親ページに戻る（無ければ新規）
      currentId = '';
      dirty = false;
      await refresh();
      if (back && byId.has(back)) await load(back);
      else startNew('');
      msg(`削除しました：${title}`);
    } catch (e) {
      msg('削除に失敗しました：' + e.message, true);
    }
  }

  // ---------- 更新履歴 ----------

  const histDlg = $('histdlg');
  let histRevs = [];     // 版の一覧（新しい順）
  let histSel = null;    // いま表示している版
  let histTab = 'view';  // 'view'（内容）| 'diff'（差分）
  const revCache = new Map();   // rev -> html

  async function getRevHtml(rev) {
    if (revCache.has(rev)) return revCache.get(rev);
    const r = await fetch(ep + '?action=revision&id=' + encodeURIComponent(currentId)
      + '&rev=' + encodeURIComponent(rev), { cache: 'no-store' });
    const j = await readJson(r);
    if (!r.ok || !j.ok) throw new Error(j.error || r.status);
    revCache.set(rev, j.html);
    return j.html;
  }

  // ---- 差分 ----
  // HTML を「行」の配列にする（見出し・箇条書き・表の行ごと）
  function htmlToLines(html) {
    const doc = new DOMParser().parseFromString('<body>' + html + '</body>', 'text/html');
    const out = [];
    const push = (el, prefix) => {
      const c = el.cloneNode(true);
      c.querySelectorAll('br').forEach(b => b.replaceWith('\n'));
      const lv = (/\bind([1-6])\b/.exec(el.className || '') || [])[1] | 0;
      c.textContent.split('\n').map(x => x.replace(/\s+/g, ' ').trim()).filter(Boolean)
        .forEach(x => out.push('　'.repeat(lv) + prefix + x));
    };
    const BLOCK = { H1: '# ', H2: '## ', H3: '### ', LI: '・', BLOCKQUOTE: '> ', PRE: '', P: '', DIV: '' };
    const walk = (node) => {
      node.childNodes.forEach(ch => {
        if (ch.nodeType === 3) {
          const t = ch.textContent.replace(/\s+/g, ' ').trim();
          if (t) out.push(t);
        } else if (ch.nodeType === 1) {
          const tag = ch.tagName;
          if (ch.classList.contains('papyru-children')) out.push('［子ページ一覧］');
          else if (ch.classList.contains('papyru-children-all')) out.push('［子ページ一覧（すべての子孫）］');
          else if (tag === 'HR') out.push('────────');
          else if (tag === 'TR') {
            const cells = Array.from(ch.cells).map(c => c.textContent.replace(/\s+/g, ' ').trim());
            out.push('｜' + cells.join('｜') + '｜');
          }
          else if (tag === 'UL' || tag === 'OL' || tag === 'TABLE' || tag === 'THEAD' || tag === 'TBODY') walk(ch);
          else if (tag === 'LI') {
            // 入れ子リストがある場合は、自分の文字と子を分ける
            const own = ch.cloneNode(true);
            own.querySelectorAll('ul,ol').forEach(x => x.remove());
            let depth = 0;
            for (let q = ch.parentNode; q; q = q.parentNode) if (q.tagName === 'LI') depth++;
            push(own, '　'.repeat(depth) + '・');
            ch.querySelectorAll(':scope > ul, :scope > ol').forEach(walk);
          }
          else if (tag in BLOCK) {
            if (ch.querySelector('p,div,ul,ol,table,h1,h2,h3,blockquote')) walk(ch);
            else push(ch, BLOCK[tag]);
          }
          else push(ch, '');
        }
      });
    };
    walk(doc.body);
    return out;
  }

  // 最長共通部分列による差分。ops: {t:'eq'|'del'|'add', s}
  function diffSeq(a, b) {
    let st = 0;
    while (st < a.length && st < b.length && a[st] === b[st]) st++;
    let ea = a.length, eb = b.length;
    while (ea > st && eb > st && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
    const A = a.slice(st, ea), B = b.slice(st, eb);
    const ops = a.slice(0, st).map(s => ({ t: 'eq', s }));
    const n = A.length, m = B.length;
    if (n * m > 4e6) {          // 大きすぎるときは単純に入れ替え扱い
      A.forEach(s => ops.push({ t: 'del', s }));
      B.forEach(s => ops.push({ t: 'add', s }));
    } else {
      const w = m + 1;
      const L = new Uint16Array((n + 1) * w);
      for (let i = n - 1; i >= 0; i--)
        for (let j = m - 1; j >= 0; j--)
          L[i * w + j] = A[i] === B[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
      let i = 0, j = 0;
      while (i < n && j < m) {
        if (A[i] === B[j]) { ops.push({ t: 'eq', s: A[i] }); i++; j++; }
        else if (L[(i + 1) * w + j] >= L[i * w + j + 1]) ops.push({ t: 'del', s: A[i++] });
        else ops.push({ t: 'add', s: B[j++] });
      }
      while (i < n) ops.push({ t: 'del', s: A[i++] });
      while (j < m) ops.push({ t: 'add', s: B[j++] });
    }
    a.slice(ea).forEach(s => ops.push({ t: 'eq', s }));
    return ops;
  }

  // 1行の中で変わった文字の範囲：[[文字列, 変更か], ...] を (旧, 新) の2通りで返す
  function charSegs(x, y) {
    const ops = diffSeq(Array.from(x), Array.from(y));
    const oldS = [], newS = [];
    const add = (arr, ch, chg) => {
      if (arr.length && arr[arr.length - 1][1] === chg) arr[arr.length - 1][0] += ch;
      else arr.push([ch, chg]);
    };
    ops.forEach(o => {
      if (o.t === 'eq') { add(oldS, o.s, false); add(newS, o.s, false); }
      else if (o.t === 'del') add(oldS, o.s, true);
      else add(newS, o.s, true);
    });
    return [oldS, newS];
  }

  function lineEl(kind, segs) {
    const d = document.createElement('div');
    d.className = 'dl ' + kind;
    segs.forEach(([txt, chg]) => {
      if (chg) { const sp = document.createElement('span'); sp.className = 'chg'; sp.textContent = txt; d.append(sp); }
      else d.append(txt);
    });
    return d;
  }

  function renderDiff(oldHtml, newHtml) {
    const box = $('histdiff');
    box.replaceChildren();
    const ops = diffSeq(htmlToLines(oldHtml), htmlToLines(newHtml));
    const nAdd = ops.filter(o => o.t === 'add').length;
    const nDel = ops.filter(o => o.t === 'del').length;
    const sum = document.createElement('div');
    sum.id = 'diffsum';
    if (!nAdd && !nDel) {
      sum.textContent = oldHtml === newHtml ? '差分はありません（同じ内容です）'
        : '文字の内容に違いはありません（書式だけが違います）';
      box.append(sum);
      return;
    }
    sum.textContent = `追加 ${nAdd} 行 ・ 削除 ${nDel} 行`;
    box.append(sum);

    // 削除の連続と追加の連続を並べ、対応する行は文字単位で色を付ける
    const rows = [];   // {kind, segs} | {skip:n}
    for (let i = 0; i < ops.length;) {
      if (ops[i].t === 'eq') { rows.push({ kind: 'eq', segs: [[ops[i].s, false]] }); i++; continue; }
      const dels = [], adds = [];
      while (i < ops.length && ops[i].t === 'del') dels.push(ops[i++].s);
      while (i < ops.length && ops[i].t === 'add') adds.push(ops[i++].s);
      const pair = Math.min(dels.length, adds.length);
      const delSegs = dels.map(x => [[x, true]]), addSegs = adds.map(x => [[x, true]]);
      for (let k = 0; k < pair; k++) {
        if (dels[k].length <= 400 && adds[k].length <= 400) {
          const [o, n] = charSegs(dels[k], adds[k]);
          // 似ていない行まで全部が色付きになるのを避ける：共通部分がほぼ無ければ行全体
          if (o.some(sg => !sg[1])) { delSegs[k] = o; addSegs[k] = n; }
        }
      }
      delSegs.forEach(sg => rows.push({ kind: 'del', segs: sg }));
      addSegs.forEach(sg => rows.push({ kind: 'add', segs: sg }));
    }
    // 変更のない行が続くところは、前後2行だけ残して畳む
    const keep = rows.map(r => r.kind !== 'eq');
    const CTX = 2;
    const show = rows.map((_, i) => { for (let d = -CTX; d <= CTX; d++) if (keep[i + d]) return true; return false; });
    for (let i = 0; i < rows.length;) {
      if (show[i]) { box.append(lineEl(rows[i].kind, rows[i].segs)); i++; continue; }
      let j = i; while (j < rows.length && !show[j]) j++;
      const sk = document.createElement('div');
      sk.className = 'dl skip';
      sk.textContent = `… 変更のない ${j - i} 行 …`;
      box.append(sk);
      i = j;
    }
  }

  async function refreshDiff() {
    const box = $('histdiff');
    if (!histSel) { box.replaceChildren(); return; }
    const idx = histRevs.findIndex(v => v.rev === histSel.rev);
    const mode = $('diffbase').value;
    try {
      let oldHtml, newHtml, label;
      if (mode === 'latest') {
        if (idx === 0) { box.textContent = 'これが現在の版です。古い版を選ぶと、現在の版との差分を表示します'; return; }
        oldHtml = await getRevHtml(histSel.rev);
        newHtml = await getRevHtml(histRevs[0].rev);
        label = `${histSel.at} → ${histRevs[0].at}（現在）`;
      } else {
        newHtml = await getRevHtml(histSel.rev);
        if (idx >= 0 && idx < histRevs.length - 1) {
          oldHtml = await getRevHtml(histRevs[idx + 1].rev);
          label = `${histRevs[idx + 1].at} → ${histSel.at}`;
        } else {
          oldHtml = '';
          label = `（最初の版です）→ ${histSel.at}`;
        }
      }
      if (!histSel || idx < 0 || histSel.rev !== histRevs[idx].rev) return;
      renderDiff(oldHtml, newHtml);
      const head = document.createElement('div');
      head.style.cssText = 'font-size:12px;color:#777;padding:0 14px 2px';
      head.textContent = '比較：' + label;
      box.prepend(head);
    } catch (e) {
      box.textContent = '差分の取得に失敗しました：' + e.message;
    }
  }

  function setHistTab(tab) {
    histTab = tab;
    $('tabView').classList.toggle('on', tab === 'view');
    $('tabDiff').classList.toggle('on', tab === 'diff');
    $('histview').hidden = tab !== 'view';
    $('histdiff').hidden = tab !== 'diff';
    $('diffbase').hidden = tab !== 'diff';
    if (tab === 'diff') refreshDiff();
  }

  async function openHistory() {
    if (!currentId) return;
    try {
      const r = await fetch(ep + '?action=history&id=' + encodeURIComponent(currentId), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      histRevs = j.revisions;
      histSel = null;
      revCache.clear();
      setHistTab('view');
      $('histtitle').textContent = `更新履歴：${titleOf(currentId) || deriveTitle()}`;
      $('histview').textContent = '';
      $('histinfo').textContent = '';
      $('histrestore').disabled = true;
      histDlg.hidden = false;
      renderHistory();
      if (histRevs.length) await showRevision(histRevs[0].rev);
    } catch (e) {
      msg('履歴の取得に失敗しました：' + e.message, true);
    }
  }

  function closeHistory() {
    histDlg.hidden = true;
    histSel = null;
  }

  function renderHistory() {
    const ul = $('histlist');
    ul.replaceChildren();
    if (!histRevs.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = '履歴はまだありません';
      ul.append(li);
      return;
    }
    histRevs.forEach((v, i) => {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.className = 'doc' + (histSel && histSel.rev === v.rev ? ' active' : '');
      b.dataset.rev = v.rev;
      b.innerHTML = '<span class="t"></span><span class="d"></span>';
      b.querySelector('.t').textContent = v.at;
      if (i === 0) {
        const tag = document.createElement('span');
        tag.className = 'cur-tag';
        tag.textContent = '現在';
        b.querySelector('.t').append(tag);
      }
      b.querySelector('.d').textContent = [v.by, v.note || v.title].filter(Boolean).join(' ・ ');
      li.append(b);
      ul.append(li);
    });
  }

  async function showRevision(rev) {
    try {
      const r = await fetch(ep + '?action=revision&id=' + encodeURIComponent(currentId)
        + '&rev=' + encodeURIComponent(rev), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      const isLatest = histRevs.length > 0 && histRevs[0].rev === rev;
      histSel = { rev, at: j.at, html: j.html, isLatest };
      $('histview').innerHTML = j.html;   // サーバーで許可タグだけに整えた内容
      $('histview').scrollTop = 0;
      $('histinfo').textContent = [j.at, j.by, j.note].filter(Boolean).join(' ・ ') + (isLatest ? '（現在の版）' : '');
      $('histrestore').disabled = isLatest;
      renderHistory();
      if (histTab === 'diff') refreshDiff();
    } catch (e) {
      $('histinfo').textContent = '版の取得に失敗しました：' + e.message;
    }
  }

  // 選んだ版の内容を編集モードで読み込む。保存すると、新しい版として履歴に加わる
  function restoreRevision() {
    if (!histSel || histSel.isLatest) return;
    if (dirty && !confirm('未保存の変更があります。この版の内容で置き換えますか？')) return;
    const { at, html } = histSel;
    closeHistory();
    editor.innerHTML = html;
    dirty = true;
    setMode('edit');
    updateTitleLabel();
    msg(`${at} の版を読み込みました。保存すると、新しい版として記録されます`);
  }

  // ---------- イベント ----------

  // ツールバー：mousedownで選択範囲を失わないようにする
  document.querySelectorAll('[data-cmd]').forEach(btn => {
    btn.addEventListener('mousedown', e => {
      e.preventDefault();
      const cmd = btn.dataset.cmd;
      let arg = btn.dataset.arg ?? null;
      if (cmd === 'createLink') {
        arg = prompt('リンク先URL（https://… ）');
        if (!arg) return;
      }
      document.execCommand(cmd, false, arg);
      editor.focus();
    });
  });

  // ---------- 子ページ一覧（埋め込み部品） ----------
  // 保存されるのは <div class="papyru-children"></div>（直下のみ）/ papyru-children-all（すべての子孫）だけ。
  // 中身は、表示のたびにこのページの子ページから作る。
  const WIDGET_SEL = '.papyru-children, .papyru-children-all';

  function renderWidgets() {
    editor.querySelectorAll(WIDGET_SEL).forEach(w => {
      const all = w.classList.contains('papyru-children-all');
      const known = !!currentId && byId.has(currentId);
      const items = [];
      if (known) {
        const walk = (pid, depth) => {
          for (const k of kids.get(pid) || []) {
            items.push({ id: k.id, title: k.title, depth });
            if (all && depth < 20) walk(k.id, depth + 1);
          }
        };
        walk(currentId, 0);
      }
      const sig = [all, known, items.map(i => i.depth + ':' + i.id + ':' + i.title).join('|')].join('#');
      if (w.dataset.sig === sig) return;   // 変わっていなければ作り直さない
      w.dataset.sig = sig;
      w.contentEditable = 'false';
      w.replaceChildren();

      const head = document.createElement('div');
      head.className = 'pc-head';
      const t = document.createElement('span');
      t.textContent = '子ページ一覧';
      const ctl = document.createElement('span');
      ctl.className = 'pc-ctl edit-only';
      const sel = document.createElement('select');
      sel.className = 'pc-kind';
      sel.title = '表示する範囲';
      [['direct', '直下のみ'], ['all', 'すべての子孫']].forEach(([v, label]) => {
        const o = document.createElement('option');
        o.value = v; o.textContent = label; o.selected = (v === 'all') === all;
        sel.append(o);
      });
      const del = document.createElement('button');
      del.className = 'pc-del';
      del.type = 'button';
      del.textContent = '✕ 削除';
      del.title = 'この一覧を本文から取り除く';
      ctl.append(sel, del);
      head.append(t, ctl);
      w.append(head);

      if (!items.length) {
        const m = document.createElement('div');
        m.className = 'pc-empty';
        m.textContent = known ? '（子ページはありません）' : '（保存すると、このページの子ページがここに表示されます）';
        w.append(m);
      }
      items.forEach(it => {
        const row = document.createElement('div');
        row.className = 'pc-row';
        row.style.paddingLeft = (it.depth * 1.4) + 'em';
        const b = document.createElement('span');
        b.className = 'pc-item';
        b.dataset.id = it.id;
        b.tabIndex = 0;
        b.setAttribute('role', 'link');
        b.textContent = it.title;
        row.append(b);
        w.append(row);
      });
    });
  }

  function insertChildrenWidget() {
    const s = getSelection();
    let top = s.rangeCount && editor.contains(s.anchorNode) ? s.anchorNode : null;
    while (top && top.parentNode !== editor) top = top.parentNode;
    const w = document.createElement('div');
    w.className = 'papyru-children';
    const p = document.createElement('p');
    p.append(document.createElement('br'));
    if (!top) editor.append(w, p);
    else if (top.nodeType === 1 && top.tagName === 'P' && !top.textContent.trim() && !top.querySelector('img,table')) top.replaceWith(w, p);
    else {
      top.after(w);
      if (!w.nextElementSibling) w.after(p);
    }
    renderWidgets();
    const next = w.nextElementSibling;
    if (next && next.tagName === 'P') placeCaret(next);
    editor.dispatchEvent(new Event('input'));
    editor.focus();
  }
  $('childrenBtn').addEventListener('mousedown', e => { e.preventDefault(); insertChildrenWidget(); });

  editor.addEventListener('click', e => {
    const item = e.target.closest && e.target.closest('.pc-item');
    if (item) { e.preventDefault(); load(item.dataset.id); return; }
    const del = e.target.closest && e.target.closest('.pc-del');
    if (del && mode === 'edit') {
      del.closest(WIDGET_SEL).remove();
      editor.dispatchEvent(new Event('input'));
    }
  });
  editor.addEventListener('keydown', e => {
    const item = e.target.closest && e.target.closest('.pc-item');
    if (item && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); load(item.dataset.id); }
  });
  editor.addEventListener('change', e => {
    if (!e.target.classList || !e.target.classList.contains('pc-kind') || mode !== 'edit') return;
    const w = e.target.closest(WIDGET_SEL);
    w.className = e.target.value === 'all' ? 'papyru-children-all' : 'papyru-children';
    editor.dispatchEvent(new Event('input'));
  });

  // ---------- 表 ----------
  function curCell() {
    const s = getSelection();
    if (!s.rangeCount) return null;
    let n = s.anchorNode;
    if (n && n.nodeType === 3) n = n.parentNode;
    const c = n && n.closest ? n.closest('td,th') : null;
    return c && editor.contains(c) ? c : null;
  }
  function makeCell(tag) {
    const c = document.createElement(tag);
    c.appendChild(document.createElement('br'));
    return c;
  }
  function placeCaret(cell) {
    const r = document.createRange();
    r.selectNodeContents(cell);
    r.collapse(true);
    const s = getSelection();
    s.removeAllRanges();
    s.addRange(r);
  }
  function insertTable() {
    let html = '<table><tbody>';
    for (let r = 0; r < 3; r++) {
      html += '<tr>' + (r === 0 ? '<th><br></th>' : '<td><br></td>').repeat(3) + '</tr>';
    }
    html += '</tbody></table><p><br></p>';
    const before = new Set(editor.querySelectorAll('table'));
    document.execCommand('insertHTML', false, html);
    const t = Array.from(editor.querySelectorAll('table')).find(x => !before.has(x));
    if (t) { const c = t.querySelector('th,td'); if (c) placeCaret(c); }
    editor.dispatchEvent(new Event('input'));
  }
  function tableOp(op) {
    const cell = curCell();
    if (!cell) { msg('先に、表のセルの中にカーソルを置いてください', true); return; }
    const row = cell.parentNode;
    const table = cell.closest('table');
    const rows = Array.from(table.rows);
    const idx = cell.cellIndex;
    let focus = cell;
    if (op === 'rowAdd') {
      const nr = document.createElement('tr');
      Array.from(row.cells).forEach(() => nr.appendChild(makeCell('td')));
      row.parentNode.insertBefore(nr, row.nextSibling);
      focus = nr.cells[Math.min(idx, nr.cells.length - 1)];
    } else if (op === 'rowDel') {
      if (rows.length <= 1) { table.remove(); focus = null; }
      else {
        const next = row.nextElementSibling || row.previousElementSibling;
        row.remove();
        focus = next.cells[Math.min(idx, next.cells.length - 1)];
      }
    } else if (op === 'colAdd') {
      rows.forEach(r => {
        const ref = r.cells[idx];
        const nc = makeCell(ref && ref.tagName === 'TH' ? 'th' : 'td');
        r.insertBefore(nc, ref ? ref.nextSibling : null);
      });
      focus = row.cells[idx + 1];
    } else if (op === 'colDel') {
      if (row.cells.length <= 1) { table.remove(); focus = null; }
      else {
        rows.forEach(r => { if (r.cells[idx]) r.cells[idx].remove(); });
        focus = row.cells[Math.min(idx, row.cells.length - 1)];
      }
    } else if (op === 'tblDel') {
      table.remove(); focus = null;
    }
    if (focus) placeCaret(focus);
    editor.focus();
    editor.dispatchEvent(new Event('input'));
  }
  // ---------- 字下げ（Tab / Shift+Tab） ----------
  const MAX_INDENT = 6;
  const levelOf = el => { const m = /\bind([1-6])\b/.exec(el.className || ''); return m ? +m[1] : 0; };
  function setLevel(el, n) {
    el.className = (el.className || '').replace(/\bind[1-6]\b/g, '').trim();
    if (n > 0) el.classList.add('ind' + n);
    if (!el.className) el.removeAttribute('class');
  }
  // 選択範囲に掛かっている要素（選択の終わりが、その要素の先頭ぴったりのときは含めない）
  function inRange(sel, selector, filter) {
    const r = sel.getRangeAt(0);
    return Array.from(editor.querySelectorAll(selector)).filter(el => {
      if (filter && !filter(el)) return false;
      if (!r.intersectsNode(el)) return false;
      if (!r.collapsed && el.contains(r.endContainer)) {
        const t = document.createRange();
        t.setStart(el, 0);
        t.setEnd(r.endContainer, r.endOffset);
        if (t.toString() === '') return false;
      }
      return true;
    });
  }
  const outermost = list => list.filter(li => !list.some(o => o !== li && o.contains(li)));

  function listIndent(lis) {
    lis.forEach(li => {
      const prev = li.previousElementSibling;
      if (!prev || prev.tagName !== 'LI') return;   // 先頭の項目は、これ以上深くできない
      let sub = prev.lastElementChild;
      if (!sub || !/^(UL|OL)$/.test(sub.tagName)) {
        sub = document.createElement(li.parentNode.tagName.toLowerCase());
        prev.appendChild(sub);
      }
      sub.appendChild(li);
    });
  }
  // 入れ子を1段浅くする。最上位の項目があれば true（段落へ戻す処理を呼び出し側で行う）
  function listOutdent(lis) {
    let top = false;
    lis.slice().reverse().forEach(li => {
      const list = li.parentNode, outer = list.parentNode;
      if (!outer || outer.tagName !== 'LI') { top = true; return; }
      const trailing = [];
      for (let n = li.nextElementSibling; n; n = n.nextElementSibling) trailing.push(n);
      if (trailing.length) {   // 後ろの項目は、この項目の子になる
        let sub = li.lastElementChild;
        if (!sub || !/^(UL|OL)$/.test(sub.tagName)) {
          sub = document.createElement(list.tagName.toLowerCase());
          li.appendChild(sub);
        }
        trailing.forEach(n => sub.appendChild(n));
      }
      outer.parentNode.insertBefore(li, outer.nextSibling);
      if (!list.children.length) list.remove();
    });
    return top;
  }

  function cellNav(cell, back) {
    const table = cell.closest('table');
    const cells = Array.from(table.querySelectorAll('th,td'));
    const i = cells.indexOf(cell);
    if (back) { if (i > 0) placeCaret(cells[i - 1]); return; }
    if (i < cells.length - 1) { placeCaret(cells[i + 1]); return; }
    tableOp('rowAdd');   // 最後のセルで Tab を押すと、行を足して先頭へ
    placeCaret(table.rows[table.rows.length - 1].cells[0]);
  }

  // dir: +1 = 字下げ（Tab） / -1 = 戻す（Shift+Tab）
  function indentSelection(dir) {
    const sel = getSelection();
    if (!sel.rangeCount || !editor.contains(sel.anchorNode)) return;
    const a = sel.anchorNode.nodeType === 3 ? sel.anchorNode.parentNode : sel.anchorNode;
    if (a.closest('pre')) { if (dir > 0) document.execCommand('insertText', false, '\t'); return; }

    const sv = { an: sel.anchorNode, ao: sel.anchorOffset, fn: sel.focusNode, fo: sel.focusOffset };
    const restore = () => {
      if (editor.contains(sv.an) && editor.contains(sv.fn)) {
        try { sel.setBaseAndExtent(sv.an, sv.ao, sv.fn, sv.fo); } catch (e) { /* 位置が変わっても続行 */ }
      }
    };
    // 選択が子リストの中だけに収まるときは、親の項目は対象にしない
    const rg = sel.getRangeAt(0);
    const lis = outermost(inRange(sel, 'li', li => !Array.from(li.children).some(c =>
      /^(UL|OL)$/.test(c.tagName) && c.contains(rg.startContainer) && c.contains(rg.endContainer))));
    const cell = curCell();
    let changed = false;

    if (lis.length) {
      if (dir > 0) listIndent(lis);
      else if (listOutdent(lis)) { restore(); document.execCommand('outdent'); }
      changed = true;
    } else if (cell && sel.focusNode && cell.contains(sel.focusNode)) {
      cellNav(cell, dir < 0);
      return;
    }
    let blocks = inRange(sel, 'p,h1,h2,h3,div',
      el => !el.querySelector('p,h1,h2,h3,div,li,table,ul,ol') && !el.closest('li') && !el.closest('table') && !el.closest(WIDGET_SEL));
    if (!lis.length && !blocks.length) {   // 行が段落になっていない（直接の文字など）
      document.execCommand('formatBlock', false, 'p');
      blocks = inRange(getSelection(), 'p,h1,h2,h3,div',
        el => !el.querySelector('p,h1,h2,h3,div,li,table,ul,ol') && !el.closest('li') && !el.closest('table') && !el.closest(WIDGET_SEL));
    }
    blocks.forEach(el => {
      const n = Math.max(0, Math.min(MAX_INDENT, levelOf(el) + dir));
      if (n !== levelOf(el)) { setLevel(el, n); changed = true; }
    });
    restore();
    if (changed) editor.dispatchEvent(new Event('input'));
  }

  let tabEscape = false;   // Esc の次の Tab は、通常どおり次の部品へ移動する（キーボードの出口）
  editor.addEventListener('keydown', e => {
    if (mode !== 'edit' || e.isComposing) return;
    if (e.target.closest && e.target.closest(WIDGET_SEL)) return;
    if (['Shift', 'Control', 'Alt', 'Meta'].includes(e.key)) return;
    if (e.key === 'Escape') { tabEscape = true; return; }
    if (e.key !== 'Tab') { tabEscape = false; return; }
    if (tabEscape) { tabEscape = false; return; }
    if (e.ctrlKey || e.altKey || e.metaKey) return;
    e.preventDefault();
    indentSelection(e.shiftKey ? -1 : 1);
  });
  $('indentBtn').addEventListener('mousedown', e => { e.preventDefault(); editor.focus(); indentSelection(1); });
  $('outdentBtn').addEventListener('mousedown', e => { e.preventDefault(); editor.focus(); indentSelection(-1); });

  $('tblInsert').addEventListener('mousedown', e => { e.preventDefault(); insertTable(); editor.focus(); });
  document.querySelectorAll('[data-tbl]').forEach(btn =>
    btn.addEventListener('mousedown', e => { e.preventDefault(); tableOp(btn.dataset.tbl); }));

  const onMouseDown = (el, fn) => el.addEventListener('mousedown', e => { e.preventDefault(); fn(); });
  onMouseDown($('pagelink'), openPicker);
  onMouseDown($('unlinkBtn'), unlinkSelection);
  onMouseDown($('popopen'), () => { if (popAnchor) openLink(popAnchor); });
  onMouseDown($('popremove'), () => {
    if (!popAnchor) return;
    removeAnchor(popAnchor);
    dirty = true;
    msg('リンクを解除しました');
    updatePop();
  });

  $('save').onclick = save;
  $('editBtn').onclick = () => setMode('edit');
  $('saveView').onclick = saveAndView;
  $('cancelEdit').onclick = cancelEdit;
  $('histBtn').onclick = openHistory;
  $('histclose').onclick = closeHistory;
  $('histrestore').onclick = restoreRevision;
  $('copyLink').onclick = copyLink;
  $('tabView').onclick = () => setHistTab('view');
  $('tabDiff').onclick = () => setHistTab('diff');
  $('diffbase').onchange = refreshDiff;
  histDlg.addEventListener('click', e => { if (e.target === histDlg) closeHistory(); });
  $('histlist').addEventListener('click', e => {
    const b = e.target.closest('button[data-rev]');
    if (b) showRevision(b.dataset.rev);
  });
  $('histview').addEventListener('click', e => { if (e.target.closest('a')) e.preventDefault(); });
  $('new').onclick = newDoc;
  $('addchild').onclick = addChild;
  $('moveBtn').onclick = openParentPicker;
  $('delBtn').onclick = deleteDoc;
  $('menu').onclick = () => document.body.classList.toggle('side-closed');
  filterEl.addEventListener('input', renderList);

  listEl.addEventListener('click', e => {
    const t = e.target.closest('button[data-toggle]');
    if (t) {   // ▶▼ で子ページの表示を切り替える
      const id = t.dataset.toggle;
      if (!collapsed.delete(id)) collapsed.add(id);
      saveCollapsed();
      renderList();
      return;
    }
    const b = e.target.closest('button[data-id]');
    if (b) load(b.dataset.id);
  });

  $('crumbs').addEventListener('click', e => {
    const b = e.target.closest('button[data-id]');
    if (b) load(b.dataset.id);
  });

  pickFilter.addEventListener('input', renderPicker);
  pickFilter.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      // フォーカスがエディタに移るため、Enter が本文に入力されないよう既定動作を止める
      e.preventDefault();
      if (e.isComposing) return;   // 日本語入力の変換確定のEnterでは選択しない
      const first = pickList.querySelector('button[data-id]:not([data-top])');
      if (first) applyChoice(first.dataset.id);
    }
  });
  pickList.addEventListener('click', e => {
    const b = e.target.closest('button[data-id]');
    if (b) applyChoice(b.dataset.id);
  });
  $('pickcancel').onclick = closePicker;
  picker.addEventListener('click', e => { if (e.target === picker) closePicker(); });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (!picker.hidden) closePicker();
    else if (!histDlg.hidden) closeHistory();
  });

  // 閲覧モード：リンクをクリックすると、そのページ（外部URLなら新しいタブ）を開く。
  // 編集モード：クリックでは移動せず（カーソルを置くだけ）、Ctrl/Cmd+クリックで開く。
  editor.addEventListener('click', e => {
    const a = e.target.closest && e.target.closest('a');
    if (!a) return;
    e.preventDefault();
    if (mode === 'view' || e.ctrlKey || e.metaKey) openLink(a);
  });

  editor.addEventListener('input', () => {
    dirty = true;
    updateTitleLabel();
  });
  document.addEventListener('selectionchange', updatePop);
  main.addEventListener('scroll', updatePop, { passive: true });
  window.addEventListener('resize', updatePop);

  // 貼り付けはプレーンテキスト化して書式の混入を防ぐ
  editor.addEventListener('paste', e => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text/plain');
    document.execCommand('insertText', false, text);
  });

  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && mode === 'edit') {
      e.preventDefault();
      save();
    }
  });

  window.addEventListener('beforeunload', e => {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });

  // 画面が狭い端末ではサイドバーを閉じた状態で始める
  if (window.innerWidth <= 720) document.body.classList.add('side-closed');
  setMode('edit');   // 起動直後は、新しいページを編集モードで開いている
  updateTitleLabel();
  // ブラウザの「戻る／進む」：URLのIDに合わせて開く
  window.addEventListener('popstate', async () => {
    const id = idFromLocation();
    let ok;
    if (id) ok = await load(id, { url: 'none' });
    else if (!currentId) ok = true;
    else if (dirty && !confirm('未保存の変更があります。破棄して新規作成しますか？')) ok = false;
    else { startNew('', { noUrl: true }); ok = true; }
    if (!ok) syncUrl(currentId, 'push');   // 移動しなかったときは、アドレスバーを元に戻す
  });

  refresh()
    .then(async () => {
      const id = INITIAL_ID || idFromLocation();
      if (!id) return;
      if (!(await load(id, { url: 'replace' }))) syncUrl('', 'replace');
    })
    .catch(e => msg('一覧の取得に失敗しました：' + e.message, true));
})();
</script>
</body>
</html>
HTML

# ---------- ルーティング ----------

# Rubyの CGI は POST のとき QUERY_STRING を読まないため、
# POST（保存）でも URL の ?action=... を拾えるようにする。
def requested_action(cgi)
  act = cgi['action'].to_s
  act = Array(CGI.parse(ENV['QUERY_STRING'].to_s)['action']).first.to_s if act.empty?
  act
end

def dispatch(cgi)
  action = requested_action(cgi)
  case action
  when 'login'    then handle_login(cgi)
  when 'callback' then handle_callback(cgi)
  when 'logout'   then handle_logout(cgi)
  when 'list', 'load', 'save', 'move', 'delete', 'history', 'revision'
    email = current_email(cgi)
    return send_json(cgi, { ok: false, error: 'login required' }, 'UNAUTHORIZED') unless email

    case action
    when 'list'     then handle_list(cgi)
    when 'load'     then handle_load(cgi)
    when 'move'     then handle_move(cgi)
    when 'delete'   then handle_delete(cgi)
    when 'history'  then handle_history(cgi)
    when 'revision' then handle_revision(cgi)
    else                 handle_save(cgi, email)
    end
  else
    email = current_email(cgi)
    rid   = requested_id(cgi)
    if email
      page = PAGE.sub('{{SCRIPT_JS}}') { js_literal(script_path) }
                 .sub('{{PERMA_JS}}') { js_literal(permalink_base) }
                 .sub('{{ID_JS}}') { js_literal(rid) }
                 .sub('{{SCRIPT_HTML}}') { CGI.escapeHTML(script_path) }
                 .sub('{{EMAIL}}') { CGI.escapeHTML(email) }
      send_html(cgi, page)
    else
      login_url = script_path + '?action=login' + (rid.empty? ? '' : "&id=#{rid}")
      send_html(cgi, LOGIN_PAGE.sub('{{LOGIN_URL}}') { CGI.escapeHTML(login_url) })
    end
  end
end

begin
  Dir.mkdir(DATA_DIR, 0o705) unless Dir.exist?(DATA_DIR)
  begin
    ht = File.join(DATA_DIR, '.htaccess')
    unless File.exist?(ht)
      File.write(ht, "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" \
                     "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n")
      File.chmod(0o604, ht)
    end
  rescue StandardError
    nil   # 書き込めなくても動作には影響しない
  end
  dispatch(CGI.new)
rescue StandardError => e
  warn "[papyru] #{e.class}: #{e.message}"
  begin
    send_html(CGI.new, html_message('エラーが発生しました', '時間をおいて再度お試しください。'), 'INTERNAL_SERVER_ERROR')
  rescue StandardError
    nil
  end
end
