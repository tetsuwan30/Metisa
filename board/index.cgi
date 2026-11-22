#!/usr/local/bin/ruby2.6
# coding: utf-8
#
# Board（オンラインホワイトボード）— Googleアカウントログイン付き
# ロリポップ！レンタルサーバー（Ruby CGI）向け。標準ライブラリのみ使用。
# wiki（Papyru）と同じ構成：ログイン・保存・一覧・履歴・パーマリンク。
#
# 設置:
#   1. このファイルを index.cgi という名前で、wikiとは別のディレクトリに置く（例: public_html/board/）
#   2. 同じディレクトリに config.json を置く（wikiの config.json をコピーして
#      redirect_uri と permalink_base を board 用に書き換える）
#        "redirect_uri":   "https://（ドメイン）/board/index.cgi?action=callback"
#        "permalink_base": "https://（ドメイン）/board/"   ← 省略可（省略時は index.cgi?id=<ID>）
#   3. パーミッション: index.cgi は 700 / config.json は 600 / ディレクトリは 705
#   4. Google Cloud Console の OAuth クライアントに、上の redirect_uri を「承認済みのリダイレクト URI」として追加
#      （wikiと同じクライアントIDを使い回してOK。URIを1行足すだけ）
#   5. https://（ドメイン）/board/index.cgi を開く
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
MAX_BYTES      = 2_000_000
SESSION_TTL    = 12 * 3600
STATE_TTL      = 600
SESSION_COOKIE = 'board_session'
STATE_COOKIE   = 'board_oauth_state'
RETURN_COOKIE  = 'board_return'

SHAPE_TYPES = %w[rect round terminator diamond parallelogram document db ellipse note frame text].freeze
COLOR_RE    = /\A#[0-9a-fA-F]{6}\z/
ITEM_ID_RE  = /\A[A-Za-z0-9_\-]{1,24}\z/
MAX_SHAPES  = 2000
MAX_LINKS   = 4000

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

def permalink_base
  b = config['permalink_base'].to_s.strip
  return nil unless b.match?(%r{\A(https?://|/)}i)
  b.end_with?('/') ? b : b + '/'
end

def board_url(id)
  base = permalink_base
  base ? base + id : "#{script_path}?id=#{id}"
end

def js_literal(value)
  JSON.generate([value.to_s])[1..-2].gsub('<') { '\u003c' }.gsub("\u2028") { '\u2028' }
end

def valid_name?(name)
  name.match?(NAME_RE)
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
  dest = valid_name?(rid) ? board_url(rid) : script_path
  send_redirect(cgi, dest,
                [make_cookie(SESSION_COOKIE, token, expires: Time.now + SESSION_TTL), clear_state,
                 make_cookie(RETURN_COOKIE, '', expires: Time.at(0))])
end

def handle_logout(cgi)
  send_redirect(cgi, script_path, [make_cookie(SESSION_COOKIE, '', expires: Time.at(0))])
end

# ---------- ボード API ----------
# ボード本体は data/<id>.json、タイトルは data/<id>.title に保存する。

def board_path(id)
  File.join(DATA_DIR, "#{id}.json")
end

def title_path(id)
  File.join(DATA_DIR, "#{id}.title")
end

def board_exists?(id)
  valid_name?(id.to_s) && File.file?(board_path(id))
end

def new_board_id
  loop do
    id = Time.now.strftime('%Y%m%d-%H%M%S') + '-' + SecureRandom.hex(3)
    return id unless File.exist?(board_path(id))
  end
end

def clean_title(raw)
  t = raw.to_s.dup.force_encoding('UTF-8').scrub.gsub(/[[:cntrl:]]+/, ' ').strip
  t = t[0, 100].to_s.strip
  t.empty? ? '無題のボード' : t
end

def read_title(id)
  path = title_path(id)
  File.file?(path) ? clean_title(File.read(path, encoding: 'utf-8')) : id
end

def num(value, min, max, default)
  f = begin
    Float(value)
  rescue ArgumentError, TypeError
    default.to_f
  end
  f = default.to_f if f.nan? || f.infinite?
  [[f, min].max, max].min.round(1)
end

def clean_text(value, max)
  s = value.to_s.dup.force_encoding('UTF-8').scrub.gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F]/, '')
  s[0, max].to_s
end

def pick_color(value, default)
  value.to_s.match?(COLOR_RE) ? value.to_s : default
end

# クライアントから届いたボードを、決まった形だけに整える（想定外のキー・値は捨てる）
def clean_board(obj)
  raise 'invalid board' unless obj.is_a?(Hash)

  raw_shapes = obj['shapes'].is_a?(Array) ? obj['shapes'] : []
  raw_links  = obj['links'].is_a?(Array) ? obj['links'] : []

  ids = {}
  shapes = raw_shapes.first(MAX_SHAPES).map do |s|
    next nil unless s.is_a?(Hash)
    id   = s['id'].to_s
    type = s['type'].to_s
    next nil unless id.match?(ITEM_ID_RE) && SHAPE_TYPES.include?(type) && !ids[id]
    ids[id] = true
    {
      'id' => id, 'type' => type,
      'x' => num(s['x'], -100_000, 100_000, 0), 'y' => num(s['y'], -100_000, 100_000, 0),
      'w' => num(s['w'], 8, 5000, 140), 'h' => num(s['h'], 8, 5000, 60),
      'text' => clean_text(s['text'], 1000),
      'fill' => pick_color(s['fill'], 'none'),
      'stroke' => pick_color(s['stroke'], '#3b4252'),
      'fs' => num(s['fs'], 8, 96, 14).round
    }
  end.compact

  link_ids = {}
  links = raw_links.first(MAX_LINKS).map do |l|
    next nil unless l.is_a?(Hash)
    id = l['id'].to_s
    from = l['from'].to_s
    to = l['to'].to_s
    next nil unless id.match?(ITEM_ID_RE) && !link_ids[id] && ids[from] && ids[to] && from != to
    link_ids[id] = true
    sides = %w[a t r b l]
    {
      'id' => id, 'from' => from, 'to' => to,
      'label' => clean_text(l['label'], 200),
      'style' => l['style'].to_s == 'straight' ? 'straight' : 'elbow',
      'dash' => l['dash'] == true,
      'arrow' => l['arrow'] != false,
      'fSide' => sides.include?(l['fSide'].to_s) ? l['fSide'].to_s : 'a',
      'tSide' => sides.include?(l['tSide'].to_s) ? l['tSide'].to_s : 'a'
    }
  end.compact

  v = obj['view'].is_a?(Hash) ? obj['view'] : {}
  view = { 'x' => num(v['x'], -100_000, 100_000, 60), 'y' => num(v['y'], -100_000, 100_000, 60),
           'z' => num(v['z'], 0.1, 4, 1) }
  { 'v' => 1, 'shapes' => shapes, 'links' => links, 'view' => view }
end

def read_board(id)
  JSON.parse(File.read(board_path(id), encoding: 'utf-8'))
rescue StandardError
  { 'v' => 1, 'shapes' => [], 'links' => [], 'view' => { 'x' => 60, 'y' => 60, 'z' => 1 } }
end

def same_origin?
  origin = ENV['HTTP_ORIGIN'].to_s
  return true if origin.empty?
  host = ENV['HTTP_HOST'].to_s
  host = ENV['SERVER_NAME'].to_s if host.empty?
  return false if host.empty?
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

# ---- 更新履歴（data/history/<ボードID>/<版ID>.json と .meta） ----
HISTORY_DIR   = File.join(DATA_DIR, 'history')
MAX_REVISIONS = 50

def history_dir(id)
  File.join(HISTORY_DIR, id)
end

def revision_ids(id)
  Dir.glob(File.join(history_dir(id), '*.json'))
     .map { |f| File.basename(f, '.json') }
     .select { |r| valid_name?(r) }
     .sort
end

def read_revision_meta(id, rev)
  JSON.parse(File.read(File.join(history_dir(id), "#{rev}.meta"), encoding: 'utf-8'))
rescue StandardError
  {}
end

def snapshot_revision(id, title, json, by, at: Time.now)
  Dir.mkdir(HISTORY_DIR, 0o700) unless Dir.exist?(HISTORY_DIR)
  dir = history_dir(id)
  Dir.mkdir(dir, 0o700) unless Dir.exist?(dir)

  if (last = revision_ids(id).last)
    last_json = File.read(File.join(dir, "#{last}.json"), encoding: 'utf-8')
    return nil if last_json == json && read_revision_meta(id, last)['title'] == title
  end

  rev  = at.strftime('%Y%m%d%H%M%S') + format('%06d', at.usec) + '-' + SecureRandom.hex(2)
  meta = { 'title' => title, 'by' => by.to_s, 'at' => at.strftime('%Y-%m-%d %H:%M:%S'), 'bytes' => json.bytesize }
  File.write(File.join(dir, "#{rev}.json"), json)
  File.write(File.join(dir, "#{rev}.meta"), JSON.generate(meta))
  File.chmod(0o600, File.join(dir, "#{rev}.json"), File.join(dir, "#{rev}.meta"))

  revs = revision_ids(id)
  revs.first([revs.length - MAX_REVISIONS, 0].max).each do |old|
    File.delete(File.join(dir, "#{old}.json")) rescue nil
    File.delete(File.join(dir, "#{old}.meta")) rescue nil
  end
  rev
end

def handle_history(cgi)
  id = cgi['id'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless board_exists?(id)

  list = revision_ids(id).reverse.map do |rev|
    m = read_revision_meta(id, rev)
    { rev: rev, title: m['title'].to_s, by: m['by'].to_s, at: m['at'].to_s, bytes: m['bytes'].to_i }
  end
  send_json(cgi, { ok: true, id: id, revisions: list })
end

def handle_revision(cgi)
  id  = cgi['id'].to_s
  rev = cgi['rev'].to_s
  unless board_exists?(id) && valid_name?(rev) && File.file?(File.join(history_dir(id), "#{rev}.json"))
    return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND')
  end
  m = read_revision_meta(id, rev)
  board = JSON.parse(File.read(File.join(history_dir(id), "#{rev}.json"), encoding: 'utf-8'))
  send_json(cgi, { ok: true, id: id, rev: rev, title: m['title'].to_s, by: m['by'].to_s, at: m['at'].to_s, board: board })
end

def updated_text(id)
  File.mtime(board_path(id)).strftime('%Y-%m-%d %H:%M')
end

def handle_list(cgi)
  docs = Dir.glob(File.join(DATA_DIR, '*.json')).map do |f|
    id = File.basename(f, '.json')
    next nil unless valid_name?(id)
    { id: id, title: read_title(id), mtime: File.mtime(f) }
  end.compact
  docs.sort_by! { |d| -d[:mtime].to_i }
  send_json(cgi, docs.map { |d| { id: d[:id], title: d[:title], updated: d[:mtime].strftime('%Y-%m-%d %H:%M') } })
end

def handle_load(cgi)
  id = cgi['id'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless board_exists?(id)
  send_json(cgi, { ok: true, id: id, title: read_title(id), board: read_board(id),
                   updated: updated_text(id), revisions: revision_ids(id).length })
end

# ボードを削除する。実ファイルは data/trash/ へ移すだけで、完全には消さない。
def handle_delete(cgi)
  return unless post_only(cgi)

  id = cgi['id'].to_s
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless board_exists?(id)

  trash = File.join(DATA_DIR, 'trash')
  Dir.mkdir(trash, 0o700) unless Dir.exist?(trash)
  stamp = Time.now.strftime('%Y%m%d%H%M%S')
  %w[json title].each do |ext|
    src = File.join(DATA_DIR, "#{id}.#{ext}")
    File.rename(src, File.join(trash, "#{stamp}_#{id}.#{ext}")) if File.file?(src)
  end
  File.rename(history_dir(id), File.join(trash, "#{stamp}_#{id}.history")) if Dir.exist?(history_dir(id))
  send_json(cgi, { ok: true, id: id })
end

def handle_save(cgi, email)
  return unless post_only(cgi)

  id    = cgi['id'].to_s.strip
  title = clean_title(cgi['title'])
  # 本文はbase64で受け取る（JSONを含むPOSTがWAF等に弾かれるのを避けるため）
  raw = cgi['data64'].to_s.unpack1('m')
  return send_json(cgi, { ok: false, error: 'empty' }, 'BAD_REQUEST') if raw.nil? || raw.empty?
  return send_json(cgi, { ok: false, error: 'too large' }, 'BAD_REQUEST') if raw.bytesize > MAX_BYTES

  begin
    board = clean_board(JSON.parse(raw.dup.force_encoding('UTF-8').scrub))
  rescue JSON::ParserError, RuntimeError
    return send_json(cgi, { ok: false, error: 'invalid board' }, 'BAD_REQUEST')
  end

  new_doc = id.empty?
  if new_doc
    id = new_board_id
  elsif !valid_name?(id)
    return send_json(cgi, { ok: false, error: 'invalid id' }, 'BAD_REQUEST')
  end

  json = JSON.generate(board)
  File.write(board_path(id), json)
  File.write(title_path(id), title)
  File.chmod(0o600, board_path(id))
  File.chmod(0o600, title_path(id))
  snapshot_revision(id, title, json, email)

  send_json(cgi, { ok: true, id: id, title: title, updated: updated_text(id), revisions: revision_ids(id).length })
end

# ---------- 画面 ----------

LOGIN_PAGE = <<~'HTML'
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Board - ログイン</title>
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
  <h1>Board</h1>
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
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Board</title>
<style>
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html, body { height: 100%; }
  body { margin: 0; display: flex; flex-direction: column; font-family: -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; background: #f2f3f5; color: #222; overscroll-behavior: none; }

  header { flex: none; background: #2f3640; color: #fff; padding: 8px 14px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  header .user { font-weight: normal; font-size: 13px; }
  header a { color: #fff; }
  header .appbtn { display: flex; align-items: center; justify-content: center; width: 36px; height: 32px; padding: 0; background: transparent;
    color: #fff; border: 1px solid #667; border-radius: 6px; cursor: pointer; }
  header .appbtn:hover, header .appbtn[aria-expanded="true"] { background: rgba(255,255,255,.14); }
  header .appbtn svg { width: 18px; height: 18px; fill: currentColor; }
  /* 右からスライドして出るアプリメニュー（Wiki・チケット管理と共通） */
  #appmenu-backdrop { position: fixed; inset: 0; z-index: 55; background: rgba(20,24,32,.4); opacity: 0; visibility: hidden;
    transition: opacity .22s ease, visibility 0s .22s; }
  #appmenu-backdrop.open { opacity: 1; visibility: visible; transition: opacity .22s ease; }
  #appmenu { position: fixed; top: 0; right: 0; bottom: 0; z-index: 60; width: min(300px, 86vw);
    display: flex; flex-direction: column; background: #fff; color: #222; font-weight: normal;
    box-shadow: -4px 0 18px rgba(0,0,0,.22); transform: translateX(100%); visibility: hidden;
    transition: transform .22s ease, visibility 0s .22s; padding-bottom: env(safe-area-inset-bottom); }
  #appmenu.open { transform: translateX(0); visibility: visible; transition: transform .22s ease; }
  @media (prefers-reduced-motion: reduce) { #appmenu, #appmenu-backdrop { transition: none !important; } }
  #appmenu .am-head { display: flex; align-items: center; justify-content: space-between; padding: 12px 14px 12px 18px;
    background: #2f3640; color: #fff; font-weight: bold; }
  #appmenu .am-head button { font: inherit; background: transparent; color: #fff; border: 1px solid #667; border-radius: 6px;
    width: 32px; height: 30px; cursor: pointer; }
  #appmenu .am-item { display: block; padding: 14px 18px; color: #222; text-decoration: none; font-size: 15px;
    border-left: 4px solid transparent; }
  #appmenu .am-item:hover, #appmenu .am-item:focus-visible { background: #f1f3f6; outline: none; }
  #appmenu .am-item.cur { border-left-color: #2f6fed; background: #eef3ff; font-weight: bold; }
  #appmenu .am-sep { height: 1px; background: #e2e5ea; margin: 8px 0; }
  #appmenu .am-user { padding: 6px 18px; font-size: 12px; color: #667; word-break: break-all; }
  #appmenu .am-out { color: #b3261e; }
  header .menu { font: inherit; background: transparent; color: #fff; border: 1px solid #667; border-radius: 4px; padding: 2px 8px; cursor: pointer; margin-right: 6px; }

  .layout { flex: 1; min-height: 0; display: flex; position: relative; }

  #sidebar { flex: none; width: 250px; background: #fff; border-right: 1px solid #ddd; display: flex; flex-direction: column; min-height: 0; }
  body.side-closed #sidebar { display: none; }
  .side-head { padding: 10px; border-bottom: 1px solid #eee; }
  .side-head input { width: 100%; font: inherit; font-size: 14px; padding: 6px 9px; border: 1px solid #bbb; border-radius: 4px; }
  #doclist, #histlist { list-style: none; margin: 0; padding: 0; overflow-y: auto; }
  #doclist { flex: 1; }
  #doclist li button, #histlist li button { display: block; width: 100%; text-align: left; font: inherit; background: transparent; border: 0; border-bottom: 1px solid #f0f0f0; padding: 9px 12px; cursor: pointer; }
  #doclist li button:hover, #histlist li button:hover { background: #f3f6fd; }
  #doclist li button.active, #histlist li button.active { background: #e3ecff; font-weight: bold; }
  .doc .t { display: block; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .doc .d { display: block; font-size: 11px; color: #888; font-weight: normal; }
  .empty { padding: 14px 12px; color: #888; font-size: 13px; }

  main { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
  .bar { flex: none; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 6px 12px; background: #fff; border-bottom: 1px solid #ddd; }
  .bar button { font: inherit; font-size: 13px; padding: 4px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; display: inline-flex; align-items: center; gap: 4px; }
  .bar button:hover { background: #eee; }
  .bar button.on { background: #e3ecff; border-color: #2f6fed; color: #1a4fc4; }
  .bar .primary { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .bar .primary:hover { background: #2a62d4; }
  .bar .danger { color: #b3261e; border-color: #e0a8a4; }
  .bar .danger:hover { background: #fdeceb; }
  .bar button:disabled { opacity: .45; cursor: default; }
  .bar .sep { width: 1px; height: 22px; background: #ccc; margin: 0 3px; }
  .bar .lbl { font-size: 12px; color: #666; }
  .bar select { font: inherit; font-size: 13px; padding: 3px 4px; }
  #title { font: inherit; font-size: 15px; font-weight: bold; padding: 4px 8px; border: 1px solid #ccc; border-radius: 4px; width: 240px; max-width: 40vw; }
  #dirty { font-size: 11px; padding: 1px 8px; border-radius: 10px; background: #fff1d6; color: #9a5b00; }
  #zoomLbl { font-size: 12px; min-width: 40px; text-align: center; color: #555; }
  #status { margin-left: auto; font-size: 13px; color: #555; }
  #status.err { color: #c0392b; }
  #palette button { padding: 3px 7px; }
  #palette button span { font-size: 12px; }
  .swatch { width: 22px; height: 22px; padding: 0 !important; border-radius: 50% !important; border: 2px solid #aaa !important; }
  .swatch.on { outline: 2px solid #2f6fed; outline-offset: 1px; }
  .swatch.none { background: linear-gradient(135deg, #fff 45%, #d64545 45%, #d64545 55%, #fff 55%) !important; }
  .swatch.ring { background: #fff !important; }

  #stage { flex: 1; min-height: 0; position: relative; overflow: hidden; background-color: #fbfbfc;
    background-image: radial-gradient(circle, #c3c9d4 1.1px, transparent 1.4px); background-size: 20px 20px; }
  #svg { width: 100%; height: 100%; display: block; touch-action: none; user-select: none; -webkit-user-select: none; }
  #stage.tool #svg { cursor: crosshair; }
  #stage.panning #svg { cursor: grab; }
  #gShapes g[data-id], #gFrames g[data-id] { cursor: move; }
  #gLinks g[data-lid] { cursor: pointer; }
  #editbox { position: absolute; z-index: 10; resize: none; overflow: hidden; border: 2px solid #2f6fed; border-radius: 4px; background: rgba(255,255,255,.96);
    font-family: "Hiragino Sans","Noto Sans JP","Yu Gothic",sans-serif; line-height: 1.35; padding: 2px 4px; outline: none; color: #222; white-space: pre-wrap; word-break: break-all; }
  #hint { position: absolute; left: 50%; top: 40%; transform: translate(-50%, -50%); text-align: center; color: #99a; font-size: 14px; line-height: 2; pointer-events: none; }
  #hint b { color: #778; }

  #histdlg { position: fixed; inset: 0; z-index: 40; background: rgba(0,0,0,.35); display: flex; align-items: center; justify-content: center; padding: 16px; }
  .hist-box { background: #fff; width: 940px; max-width: 100%; height: 80vh; border-radius: 8px; display: flex; flex-direction: column; padding: 14px; gap: 10px; }
  .hist-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .hist-head .t { font-weight: bold; }
  .hist-body { flex: 1; min-height: 0; display: flex; gap: 12px; }
  #histlist { flex: none; width: 250px; border: 1px solid #eee; border-radius: 4px; }
  .hist-pane { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; gap: 6px; }
  #histinfo { font-size: 13px; color: #555; }
  #histview { flex: 1; min-height: 0; overflow: auto; border: 1px solid #eee; border-radius: 4px; background: #fff; }
  #histview svg { width: 100%; height: 100%; display: block; }
  .hist-box button.act { font: inherit; font-size: 14px; padding: 5px 12px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; align-self: flex-end; }
  .hist-box button.act.primary { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .hist-box button.act:disabled { opacity: .45; cursor: default; }
  .cur-tag { font-size: 10px; background: #2f6fed; color: #fff; border-radius: 8px; padding: 0 6px; margin-left: 6px; font-weight: normal; vertical-align: 1px; }

  @media (max-width: 720px) {
    #sidebar { position: absolute; z-index: 20; top: 0; bottom: 0; left: 0; box-shadow: 2px 0 10px rgba(0,0,0,.2); }
    header { flex-wrap: nowrap; padding: 6px 10px; }
    header .uemail { display: none; }
    .bar { flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; padding: 5px 8px; }
    .bar::-webkit-scrollbar { display: none; }
    .bar > * { flex: 0 0 auto; }
    .bar button { white-space: nowrap; }
    #title { width: 180px; }
    .hist-body { flex-direction: column; }
    #histlist { width: auto; max-height: 28%; flex: none; }
    #status { display: none; position: fixed; left: 10px; right: 10px; bottom: 14px; z-index: 40; margin: 0;
      padding: 9px 12px; background: rgba(35,40,52,.94); color: #fff; border-radius: 8px; font-size: 13px; line-height: 1.5; pointer-events: none; }
    #status.show:not(:empty) { display: block; }
    #status.err { background: #b3261e; color: #fff; }
  }
</style>
</head>
<body>
<header>
  <span><button id="menu" class="menu" title="ボード一覧の表示／非表示">☰</button>Board（ホワイトボード）</span>
  <button id="appmenuBtn" class="appbtn" type="button" aria-label="アプリメニューを開く" aria-haspopup="true"
          aria-expanded="false" aria-controls="appmenu" title="アプリの切り替え・ログアウト">
    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="5" r="2"/><circle cx="12" cy="5" r="2"/><circle cx="19" cy="5" r="2"/>
      <circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/>
      <circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/></svg>
  </button>
</header>

<div id="appmenu-backdrop"></div>
<nav id="appmenu" aria-label="アプリメニュー">
  <div class="am-head"><span>メニュー</span><button id="appmenuClose" type="button" aria-label="閉じる">✕</button></div>
  <a class="am-item" href="/wiki/">Wiki</a>
  <a class="am-item" href="/ticket/">チケット管理</a>
  <a class="am-item cur" href="/board/" aria-current="page">ホワイトボード</a>
  <div class="am-sep"></div>
  <div class="am-user">{{EMAIL}}</div>
  <a class="am-item am-out" href="{{SCRIPT_HTML}}?action=logout">ログアウト</a>
</nav>

<div class="layout">
  <aside id="sidebar">
    <div class="side-head"><input id="filter" type="search" placeholder="タイトルで絞り込み"></div>
    <ul id="doclist"></ul>
  </aside>

  <main>
    <div class="bar" id="actbar">
      <input id="title" placeholder="ボードのタイトル" maxlength="100">
      <span id="dirty" hidden>未保存</span>
      <button id="save" class="primary">保存 (Ctrl+S)</button>
      <button id="new">新規</button>
      <button id="histBtn" title="このボードの更新履歴">履歴</button>
      <button id="copyLink" title="このボードのリンクをコピー">🔗 リンク</button>
      <span class="sep"></span>
      <button id="undoBtn" title="元に戻す (Ctrl+Z)">↶</button>
      <button id="redoBtn" title="やり直し (Ctrl+Shift+Z)">↷</button>
      <span class="sep"></span>
      <button id="zoomOut" title="縮小">−</button><span id="zoomLbl">100%</span><button id="zoomIn" title="拡大">＋</button>
      <button id="fitBtn" title="全体を表示">全体</button>
      <button id="snapBtn" class="on" title="10pxのグリッドに吸着">吸着</button>
      <span class="sep"></span>
      <button id="expPng" title="PNG画像として書き出す">PNG</button>
      <button id="expSvg" title="SVGとして書き出す">SVG</button>
      <button id="delBtn" class="danger" title="このボードを削除">削除</button>
      <span id="status"></span>
    </div>
    <div class="bar" id="palette"></div>
    <div class="bar" id="propbar" hidden></div>

    <div id="stage">
      <svg id="svg" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="#444"/>
          </marker>
          <filter id="shadow" x="-10%" y="-10%" width="125%" height="130%">
            <feDropShadow dx="2" dy="3" stdDeviation="2.5" flood-color="#000" flood-opacity=".22"/>
          </filter>
        </defs>
        <g id="world"><g id="gFrames"></g><g id="gLinks"></g><g id="gShapes"></g><g id="gUI"></g></g>
      </svg>
      <textarea id="editbox" hidden spellcheck="false"></textarea>
      <div id="hint">
        <b>ダブルクリック</b>で図形を追加　／　上のボタンで図形を選んでドラッグ<br>
        図形を選ぶと周りに●が出ます。<b>●をドラッグ</b>すると線でつながり、空きスペースで離すと次の図形ができます
      </div>
    </div>
  </main>
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
        <div id="histview"></div>
        <button class="act primary" id="histrestore" disabled>この版を編集用に読み込む</button>
      </div>
    </div>
  </div>
</div>

<script>
(() => {
  const $ = id => document.getElementById(id);
  const ep = {{SCRIPT_JS}};
  const PERMA_BASE = {{PERMA_JS}};
  const INITIAL_ID = {{ID_JS}};
  const NAME_RE = /^[A-Za-z0-9_-]{1,50}$/;
  const NS = 'http://www.w3.org/2000/svg';
  const stage = $('stage'), svg = $('svg'), gWorld = $('world');
  const gFrames = $('gFrames'), gLinks = $('gLinks'), gShapes = $('gShapes'), gUI = $('gUI');
  const editbox = $('editbox'), statusEl = $('status'), listEl = $('doclist'), filterEl = $('filter'), titleIn = $('title');

  const FONT = '"Hiragino Sans","Noto Sans JP","Yu Gothic",sans-serif';
  const DEF_STROKE = '#3b4252';
  const TYPES = {
    rect:          { label: '処理',     w: 140, h: 60 },
    round:         { label: '角丸',     w: 140, h: 60 },
    terminator:    { label: '開始/終了', w: 140, h: 48 },
    diamond:       { label: '判断',     w: 140, h: 90 },
    parallelogram: { label: '入出力',   w: 150, h: 60 },
    document:      { label: '書類',     w: 140, h: 70 },
    db:            { label: 'DB',       w: 90,  h: 90 },
    ellipse:       { label: '楕円',     w: 120, h: 70 },
    note:          { label: '付箋',     w: 140, h: 100 },
    frame:         { label: '枠',       w: 320, h: 200 },
    text:          { label: '文字',     w: 140, h: 36 },
  };
  const FILLS = ['#ffffff', '#e3ecff', '#e0f5e6', '#fff3a3', '#ffe0d6', '#f1e1ff', '#e6e6e6', 'none'];
  const STROKES = ['#3b4252', '#2f6fed', '#2e9d4f', '#d64545', '#e08a00', '#8a4fd6', '#888888'];
  const SIZES = [12, 14, 16, 18, 20, 24, 32];

  // ---------- 状態 ----------
  let shapes = [], links = [];
  let view = { x: 60, y: 60, z: 1 };
  let sel = new Set(), selLink = '';
  let currentId = '', dirty = false, saving = false, docs = [];
  let tool = 'select', snap = true;
  let undoStack = [], redoStack = [];
  let clip = null, pasteN = 0;
  let drag = null, editing = null, spaceDown = false, pinch = null;
  const ptrs = new Map();

  const mk = (tag, attrs, parent) => {
    const el = document.createElementNS(NS, tag);
    for (const k in (attrs || {})) el.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(el);
    return el;
  };
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const uid = () => 's' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-3);
  const byId = id => shapes.find(s => s.id === id);
  const linkById = id => links.find(l => l.id === id);
  const sn = v => snap ? Math.round(v / 10) * 10 : v;

  let statusTimer = null;
  const msg = (text, err = false) => {
    statusEl.textContent = text;
    statusEl.className = (err ? 'err ' : '') + 'show';
    clearTimeout(statusTimer);
    statusTimer = setTimeout(() => statusEl.classList.remove('show'), err ? 9000 : 4000);
  };

  async function readJson(r) {
    const text = await r.text();
    try { return JSON.parse(text); }
    catch (_) {
      const snippet = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
      throw new Error(`サーバーの応答が不正です（HTTP ${r.status}）${snippet ? '：' + snippet : '（本文なし）'}`);
    }
  }
  function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  // ---------- 文字の折り返し ----------
  const mctx = document.createElement('canvas').getContext('2d');
  const wrapCache = new Map();
  function wrapText(text, maxW, fs, bold) {
    const key = fs + '|' + (bold ? 1 : 0) + '|' + Math.round(maxW) + '|' + text;
    if (wrapCache.has(key)) return wrapCache.get(key);
    mctx.font = `${bold ? 'bold ' : ''}${fs}px ${FONT}`;
    const width = t => mctx.measureText(t).width;
    const out = [];
    for (const para of String(text).split('\n')) {
      if (para === '') { out.push(''); continue; }
      const toks = para.match(/[A-Za-z0-9_'’.,:;!?()\-\/@#%&+=<>]+|\s+|[\s\S]/gu) || [];
      let line = '';
      const pushLong = t => {   // 幅を超える長い語は、文字ごとに折り返す
        for (const ch of t) {
          if (line && width(line + ch) > maxW) { out.push(line); line = ''; }
          line += ch;
        }
      };
      for (const t of toks) {
        if (/^\s+$/.test(t)) { if (line) line += ' '; continue; }
        if (!line || width(line + t) <= maxW) {
          if (!line && width(t) > maxW) pushLong(t); else line += t;
        } else {
          out.push(line.trimEnd());
          line = '';
          if (width(t) > maxW) pushLong(t); else line = t;
        }
      }
      out.push(line.trimEnd());
    }
    if (wrapCache.size > 3000) wrapCache.clear();
    wrapCache.set(key, out);
    return out;
  }

  // 図形ごとの、文字を入れる領域
  function textBox(s) {
    const { w, h } = s;
    switch (s.type) {
      case 'frame':         return { cx: 12, top: 10, maxW: w - 24, anchor: 'start' };
      case 'diamond':       return { cx: w / 2, cy: h / 2, maxW: w * 0.56 };
      case 'ellipse':       return { cx: w / 2, cy: h / 2, maxW: w * 0.76 };
      case 'parallelogram': return { cx: w / 2, cy: h / 2, maxW: w * 0.68 };
      case 'terminator':    return { cx: w / 2, cy: h / 2, maxW: w - Math.min(h * 0.8, w * 0.4) };
      case 'document':      return { cx: w / 2, cy: (h - 10) / 2, maxW: w - 16 };
      case 'db':            return { cx: w / 2, cy: h / 2 + Math.min(14, h / 6) / 2, maxW: w - 16 };
      default:              return { cx: w / 2, cy: h / 2, maxW: w - 16 };
    }
  }
  const lineH = fs => fs * 1.35;
  function textLines(s) {
    return wrapText(s.text || '', Math.max(10, textBox(s).maxW), s.fs || 14, s.type === 'frame');
  }

  // ---------- 図形の描画 ----------
  function bodyEl(s, sw = 2) {
    const { w, h } = s;
    const fill = s.fill || 'none', stroke = s.stroke || DEF_STROKE;
    const a = { fill, stroke, 'stroke-width': sw, 'stroke-linejoin': 'round', style: 'pointer-events:all' };
    switch (s.type) {
      case 'rect':  return mk('rect', { x: 0, y: 0, width: w, height: h, rx: 2, ...a });
      case 'round': return mk('rect', { x: 0, y: 0, width: w, height: h, rx: Math.min(14, h / 3), ...a });
      case 'terminator': return mk('rect', { x: 0, y: 0, width: w, height: h, rx: h / 2, ...a });
      case 'ellipse': return mk('ellipse', { cx: w / 2, cy: h / 2, rx: w / 2, ry: h / 2, ...a });
      case 'diamond': return mk('polygon', { points: `${w / 2},0 ${w},${h / 2} ${w / 2},${h} 0,${h / 2}`, ...a });
      case 'parallelogram': {
        const k = Math.min(w * 0.2, 30);
        return mk('polygon', { points: `${k},0 ${w},0 ${w - k},${h} 0,${h}`, ...a });
      }
      case 'document':
        return mk('path', { d: `M0,0 H${w} V${h - 10} Q${w * 0.75},${h - 22} ${w / 2},${h - 10} T0,${h - 10} Z`, ...a });
      case 'db': {
        const ry = Math.min(14, h / 6);
        const g = mk('g');
        mk('path', { d: `M0,${ry} A${w / 2},${ry} 0 0 1 ${w},${ry} V${h - ry} A${w / 2},${ry} 0 0 1 0,${h - ry} Z`, ...a }, g);
        mk('path', { d: `M0,${ry} A${w / 2},${ry} 0 0 0 ${w},${ry}`, fill: 'none', stroke, 'stroke-width': sw, style: 'pointer-events:none' }, g);
        return g;
      }
      case 'note':
        return mk('rect', { x: 0, y: 0, width: w, height: h, rx: 2, ...a, filter: 'url(#shadow)' });
      case 'frame': {
        const g = mk('g');
        mk('rect', { x: 0, y: 0, width: w, height: h, rx: 6, fill, stroke, 'stroke-width': 1.5 * sw / 2,
          'stroke-dasharray': '8 5', style: 'pointer-events:visibleStroke' }, g);
        mk('rect', { x: 0, y: 0, width: w, height: 30, fill: 'transparent', style: 'pointer-events:all' }, g);
        return g;
      }
      default:  // text
        return mk('rect', { x: 0, y: 0, width: w, height: h, fill: 'transparent', stroke: 'none', style: 'pointer-events:all' });
    }
  }

  function shapeEl(s) {
    const g = mk('g', { 'data-id': s.id, transform: `translate(${s.x} ${s.y})` });
    g.appendChild(bodyEl(s));
    if (s.text) {
      const tb = textBox(s), fs = s.fs || 14, lh = lineH(fs), lines = textLines(s);
      const t = mk('text', { 'font-size': fs, 'font-family': FONT, fill: '#222', 'text-anchor': tb.anchor || 'middle',
        'pointer-events': 'none' }, g);
      if (s.type === 'frame') t.setAttribute('font-weight', 'bold');
      lines.forEach((ln, i) => {
        const y = tb.top !== undefined ? tb.top + fs * 0.95 + i * lh
                                       : tb.cy + (i - (lines.length - 1) / 2) * lh + fs * 0.35;
        const sp = mk('tspan', { x: tb.cx, y }, t);
        sp.textContent = ln === '' ? '\u00a0' : ln;
      });
    }
    return g;
  }

  // ---------- 線（コネクタ） ----------
  const ST = 24;
  function anchor(s, side) {
    switch (side) {
      case 't': return { p: { x: s.x + s.w / 2, y: s.y }, d: { x: 0, y: -1 } };
      case 'b': return { p: { x: s.x + s.w / 2, y: s.y + s.h }, d: { x: 0, y: 1 } };
      case 'l': return { p: { x: s.x, y: s.y + s.h / 2 }, d: { x: -1, y: 0 } };
      default:  return { p: { x: s.x + s.w, y: s.y + s.h / 2 }, d: { x: 1, y: 0 } };
    }
  }
  function autoSides(a, b) {
    const dx = (b.x + b.w / 2) - (a.x + a.w / 2), dy = (b.y + b.h / 2) - (a.y + a.h / 2);
    if (Math.abs(dx) / (a.w / 2 + b.w / 2) > Math.abs(dy) / (a.h / 2 + b.h / 2)) return dx >= 0 ? ['r', 'l'] : ['l', 'r'];
    return dy >= 0 ? ['b', 't'] : ['t', 'b'];
  }
  const swapXY = p => ({ x: p.y, y: p.x });
  function elbowH(p, q, a, b) {   // a, b: p と q が出ていく向き（x方向に±1）
    if (a === b) {
      const xm = a > 0 ? Math.max(p.x, q.x) + ST : Math.min(p.x, q.x) - ST;
      return [p, { x: xm, y: p.y }, { x: xm, y: q.y }, q];
    }
    if (a * (q.x - p.x) > 0) {
      const mx = (p.x + q.x) / 2;
      return [p, { x: mx, y: p.y }, { x: mx, y: q.y }, q];
    }
    const my = (p.y + q.y) / 2 + (Math.abs(p.y - q.y) < 1 ? ST * 2 : 0);
    const s1 = { x: p.x + a * ST, y: p.y }, s2 = { x: q.x + b * ST, y: q.y };
    return [p, s1, { x: s1.x, y: my }, { x: s2.x, y: my }, s2, q];
  }
  function routePts(l, map) {
    const A = map.get(l.from), B = map.get(l.to);
    if (!A || !B) return null;
    const auto = autoSides(A, B);
    const sa = l.fSide && l.fSide !== 'a' ? l.fSide : auto[0];
    const sb = l.tSide && l.tSide !== 'a' ? l.tSide : auto[1];
    const P = anchor(A, sa), Q = anchor(B, sb);
    const p = P.p, q = Q.p, d1 = P.d, d2 = Q.d;
    if (l.style === 'straight') return [p, q];
    const h1 = d1.x !== 0, h2 = d2.x !== 0;
    let pts;
    if (h1 && h2) pts = elbowH(p, q, d1.x, d2.x);
    else if (!h1 && !h2) pts = elbowH(swapXY(p), swapXY(q), d1.y, d2.y).map(swapXY);
    else if (h1 && !h2) {
      if (d1.x * (q.x - p.x) > 0 && d2.y * (p.y - q.y) > 0) pts = [p, { x: q.x, y: p.y }, q];
      else {
        const s1 = { x: p.x + d1.x * ST, y: p.y }, s2 = { x: q.x, y: q.y + d2.y * ST };
        pts = [p, s1, { x: s1.x, y: s2.y }, s2, q];
      }
    } else {
      if (d1.y * (q.y - p.y) > 0 && d2.x * (p.x - q.x) > 0) pts = [p, { x: p.x, y: q.y }, q];
      else {
        const s1 = { x: p.x, y: p.y + d1.y * ST }, s2 = { x: q.x + d2.x * ST, y: q.y };
        pts = [p, s1, { x: s2.x, y: s1.y }, s2, q];
      }
    }
    return pts.filter((pt, i) => i === 0 || Math.abs(pt.x - pts[i - 1].x) > 0.01 || Math.abs(pt.y - pts[i - 1].y) > 0.01);
  }
  function pathD(pts, r = 8) {
    if (!pts || pts.length < 2) return '';
    let d = `M${pts[0].x},${pts[0].y}`;
    for (let i = 1; i < pts.length - 1; i++) {
      const a = pts[i - 1], b = pts[i], c = pts[i + 1];
      const l1 = Math.hypot(b.x - a.x, b.y - a.y), l2 = Math.hypot(c.x - b.x, c.y - b.y);
      const rr = Math.min(r, l1 / 2, l2 / 2);
      if (rr < 1) { d += ` L${b.x},${b.y}`; continue; }
      d += ` L${b.x - (b.x - a.x) / l1 * rr},${b.y - (b.y - a.y) / l1 * rr}`
        + ` Q${b.x},${b.y} ${b.x + (c.x - b.x) / l2 * rr},${b.y + (c.y - b.y) / l2 * rr}`;
    }
    const z = pts[pts.length - 1];
    return d + ` L${z.x},${z.y}`;
  }
  function midpoint(pts) {
    let total = 0;
    for (let i = 1; i < pts.length; i++) total += Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    let half = total / 2;
    for (let i = 1; i < pts.length; i++) {
      const seg = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
      if (half <= seg && seg > 0) {
        const t = half / seg;
        return { x: pts[i - 1].x + (pts[i].x - pts[i - 1].x) * t, y: pts[i - 1].y + (pts[i].y - pts[i - 1].y) * t };
      }
      half -= seg;
    }
    return pts[0];
  }

  function linkEl(l, map, interactive) {
    const pts = routePts(l, map);
    if (!pts) return null;
    const d = pathD(pts);
    const g = mk('g', interactive ? { 'data-lid': l.id } : {});
    if (interactive) mk('path', { d, fill: 'none', stroke: 'transparent', 'stroke-width': 14, style: 'pointer-events:stroke' }, g);
    const p = mk('path', { d, fill: 'none', stroke: '#444', 'stroke-width': 2, 'stroke-linejoin': 'round',
      style: 'pointer-events:none' }, g);
    if (l.dash) p.setAttribute('stroke-dasharray', '7 5');
    if (l.arrow !== false) p.setAttribute('marker-end', 'url(#arrow)');
    if (l.label) {
      const m = midpoint(pts);
      mctx.font = `13px ${FONT}`;
      const lines = String(l.label).split('\n');
      const wd = Math.max(...lines.map(t => mctx.measureText(t).width)) + 12, ht = lines.length * 17 + 4;
      mk('rect', { x: m.x - wd / 2, y: m.y - ht / 2, width: wd, height: ht, rx: 4, fill: '#fff', stroke: '#d5d9e0',
        'stroke-width': 1, style: 'pointer-events:none' }, g);
      const t = mk('text', { 'font-size': 13, 'font-family': FONT, 'text-anchor': 'middle', fill: '#333', style: 'pointer-events:none' }, g);
      lines.forEach((ln, i) => {
        const sp = mk('tspan', { x: m.x, y: m.y - ht / 2 + 2 + 13 + i * 17 }, t);
        sp.textContent = ln;
      });
    }
    return g;
  }

  function drawInto(fr, lk, sh, S, L, interactive) {
    const map = new Map(S.map(s => [s.id, s]));
    for (const s of S) (s.type === 'frame' ? fr : sh).appendChild(shapeEl(s));
    for (const l of L) { const el = linkEl(l, map, interactive); if (el) lk.appendChild(el); }
  }

  function render() {
    gFrames.replaceChildren(); gLinks.replaceChildren(); gShapes.replaceChildren();
    drawInto(gFrames, gLinks, gShapes, shapes, links, true);
    $('hint').hidden = shapes.length > 0 || !!drag;
    renderUI();
  }

  // ---------- 選択枠・ハンドル ----------
  const CURSORS = { nw: 'nwse-resize', se: 'nwse-resize', ne: 'nesw-resize', sw: 'nesw-resize', n: 'ns-resize', s: 'ns-resize', e: 'ew-resize', w: 'ew-resize' };
  function renderUI() {
    gUI.replaceChildren();
    const z = view.z, px = 1 / z;
    const none = { 'pointer-events': 'none' };
    if (selLink) {
      const l = linkById(selLink), pts = l && routePts(l, new Map(shapes.map(s => [s.id, s])));
      if (pts) mk('path', { d: pathD(pts), fill: 'none', stroke: '#2f6fed', 'stroke-width': 6 * px, opacity: .35, ...none }, gUI);
    }
    for (const id of sel) {
      const s = byId(id);
      if (!s) continue;
      mk('rect', { x: s.x - 3 * px, y: s.y - 3 * px, width: s.w + 6 * px, height: s.h + 6 * px, fill: 'none', stroke: '#2f6fed',
        'stroke-width': 1.5 * px, 'stroke-dasharray': `${5 * px} ${4 * px}`, ...none }, gUI);
    }
    if (sel.size === 1 && !editing && !drag) {
      const s = byId([...sel][0]);
      if (s) {
        for (const [k, fx, fy] of [['nw', 0, 0], ['n', .5, 0], ['ne', 1, 0], ['e', 1, .5], ['se', 1, 1], ['s', .5, 1], ['sw', 0, 1], ['w', 0, .5]]) {
          mk('rect', { x: s.x + s.w * fx - 4.5 * px, y: s.y + s.h * fy - 4.5 * px, width: 9 * px, height: 9 * px, fill: '#fff',
            stroke: '#2f6fed', 'stroke-width': 1.5 * px, 'data-h': k, style: `cursor:${CURSORS[k]}` }, gUI);
        }
        if (s.type !== 'frame') {
          const off = 20 * px;
          for (const [k, fx, fy, dx, dy] of [['t', .5, 0, 0, -off], ['r', 1, .5, off, 0], ['b', .5, 1, 0, off], ['l', 0, .5, -off, 0]]) {
            mk('circle', { cx: s.x + s.w * fx + dx, cy: s.y + s.h * fy + dy, r: 7 * px, fill: '#2f6fed', stroke: '#fff',
              'stroke-width': 2 * px, 'data-c': k, style: 'cursor:crosshair' }, gUI);
          }
        }
      }
    }
    if (drag) {
      if (drag.k === 'create') {
        const x = Math.min(drag.x0, drag.x1), y = Math.min(drag.y0, drag.y1);
        mk('rect', { x, y, width: Math.abs(drag.x1 - drag.x0), height: Math.abs(drag.y1 - drag.y0), fill: 'rgba(47,111,237,.08)',
          stroke: '#2f6fed', 'stroke-width': 1.5 * px, 'stroke-dasharray': `${5 * px} ${4 * px}`, ...none }, gUI);
      } else if (drag.k === 'marquee') {
        mk('rect', { x: Math.min(drag.x0, drag.x1), y: Math.min(drag.y0, drag.y1), width: Math.abs(drag.x1 - drag.x0),
          height: Math.abs(drag.y1 - drag.y0), fill: 'rgba(47,111,237,.08)', stroke: '#2f6fed', 'stroke-width': px, ...none }, gUI);
      } else if (drag.k === 'link') {
        const s = byId(drag.from);
        if (s) {
          const a = anchor(s, drag.side).p;
          mk('line', { x1: a.x, y1: a.y, x2: drag.x, y2: drag.y, stroke: '#2f6fed', 'stroke-width': 2 * px,
            'stroke-dasharray': `${6 * px} ${4 * px}`, ...none }, gUI);
        }
        const h = drag.hot && byId(drag.hot);
        if (h) mk('rect', { x: h.x - 4 * px, y: h.y - 4 * px, width: h.w + 8 * px, height: h.h + 8 * px, rx: 4 * px, fill: 'rgba(46,157,79,.12)',
          stroke: '#2e9d4f', 'stroke-width': 2.5 * px, ...none }, gUI);
      }
    }
  }

  // ---------- 表示（パン・ズーム） ----------
  function applyView() {
    gWorld.setAttribute('transform', `translate(${view.x} ${view.y}) scale(${view.z})`);
    const g = 20 * view.z;
    stage.style.backgroundSize = `${g}px ${g}px`;
    stage.style.backgroundPosition = `${view.x}px ${view.y}px`;
    stage.style.backgroundImage = g < 7 ? 'none' : '';
    $('zoomLbl').textContent = Math.round(view.z * 100) + '%';
    if (!editing) renderUI();
  }
  function toWorld(e) {
    const r = svg.getBoundingClientRect();
    return { x: (e.clientX - r.left - view.x) / view.z, y: (e.clientY - r.top - view.y) / view.z };
  }
  function zoomAt(cx, cy, f) {
    const nz = clamp(view.z * f, 0.15, 3);
    const wx = (cx - view.x) / view.z, wy = (cy - view.y) / view.z;
    view.z = nz; view.x = cx - wx * nz; view.y = cy - wy * nz;
    applyView();
  }
  function bboxOf(S, L) {
    if (!S.length) return null;
    let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    for (const s of S) { x1 = Math.min(x1, s.x); y1 = Math.min(y1, s.y); x2 = Math.max(x2, s.x + s.w); y2 = Math.max(y2, s.y + s.h); }
    if (L) {
      const map = new Map(S.map(s => [s.id, s]));
      for (const l of L) for (const p of (routePts(l, map) || [])) { x1 = Math.min(x1, p.x); y1 = Math.min(y1, p.y); x2 = Math.max(x2, p.x); y2 = Math.max(y2, p.y); }
    }
    return { x: x1, y: y1, w: Math.max(1, x2 - x1), h: Math.max(1, y2 - y1) };
  }
  function fit() {
    const b = bboxOf(shapes);
    if (!b) { view = { x: 60, y: 60, z: 1 }; applyView(); return; }
    const r = svg.getBoundingClientRect();
    const z = clamp(Math.min((r.width - 80) / b.w, (r.height - 80) / b.h), 0.15, 1.5);
    view = { z, x: (r.width - b.w * z) / 2 - b.x * z, y: (r.height - b.h * z) / 2 - b.y * z };
    applyView();
  }
  function startPinch() {
    const [a, b] = [...ptrs.values()];
    pinch = { d0: Math.hypot(a.x - b.x, a.y - b.y) || 1, z0: view.z, vx: view.x, vy: view.y, m0: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
  }
  function doPinch() {
    const [a, b] = [...ptrs.values()];
    const d = Math.hypot(a.x - b.x, a.y - b.y) || 1, m = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    const r = svg.getBoundingClientRect();
    const nz = clamp(pinch.z0 * d / pinch.d0, 0.15, 3);
    const wx = (pinch.m0.x - r.left - pinch.vx) / pinch.z0, wy = (pinch.m0.y - r.top - pinch.vy) / pinch.z0;
    view.z = nz; view.x = m.x - r.left - wx * nz; view.y = m.y - r.top - wy * nz;
    applyView();
  }

  // ---------- 元に戻す／やり直し ----------
  const snapshot = () => JSON.stringify({ shapes, links });
  function markDirty(v = true) { dirty = v; $('dirty').hidden = !v; }
  function commit() {
    const s = snapshot();
    if (s === undoStack[undoStack.length - 1]) return;
    undoStack.push(s);
    if (undoStack.length > 100) undoStack.shift();
    redoStack = [];
    markDirty();
    updateUndoButtons();
  }
  function restore(s) {
    const o = JSON.parse(s);
    shapes = o.shapes; links = o.links;
    sel = new Set([...sel].filter(id => byId(id)));
    if (selLink && !linkById(selLink)) selLink = '';
    render(); updateProps();
  }
  function undo() {
    commitEdit();
    if (undoStack.length < 2) return;
    redoStack.push(undoStack.pop());
    restore(undoStack[undoStack.length - 1]);
    markDirty(); updateUndoButtons();
  }
  function redo() {
    commitEdit();
    if (!redoStack.length) return;
    const s = redoStack.pop();
    undoStack.push(s);
    restore(s);
    markDirty(); updateUndoButtons();
  }
  function updateUndoButtons() {
    $('undoBtn').disabled = undoStack.length < 2;
    $('redoBtn').disabled = !redoStack.length;
  }
  function resetHistory() { undoStack = [snapshot()]; redoStack = []; updateUndoButtons(); }

  // ---------- 図形の操作 ----------
  function newShape(type, x, y, w, h) {
    return {
      id: uid(), type, x, y, w, h, text: '',
      fill: type === 'note' ? '#fff3a3' : (type === 'frame' || type === 'text' ? 'none' : '#ffffff'),
      stroke: type === 'note' ? '#d9b800' : (type === 'frame' ? '#8a94a8' : DEF_STROKE),
      fs: 14,
    };
  }
  const inside = (o, f) => o.id !== f.id && o.x >= f.x && o.y >= f.y && o.x + o.w <= f.x + f.w && o.y + o.h <= f.y + f.h;

  function selectOnly(id) { sel = new Set(id ? [id] : []); selLink = ''; renderUI(); updateProps(); }

  function deleteSelection() {
    if (selLink) { links = links.filter(l => l.id !== selLink); selLink = ''; }
    else if (sel.size) {
      links = links.filter(l => !sel.has(l.from) && !sel.has(l.to));
      shapes = shapes.filter(s => !sel.has(s.id));
      sel = new Set();
    } else return;
    render(); commit(); updateProps();
  }

  function copySel() {
    if (!sel.size) return false;
    const S = shapes.filter(s => sel.has(s.id)).map(s => ({ ...s }));
    clip = { shapes: S, links: links.filter(l => sel.has(l.from) && sel.has(l.to)).map(l => ({ ...l })) };
    pasteN = 0;
    return true;
  }
  function paste() {
    if (!clip || !clip.shapes.length) return;
    pasteN++;
    const map = new Map(), off = 20 * pasteN;
    const S = clip.shapes.map(s => { const n = { ...s, id: uid(), x: s.x + off, y: s.y + off }; map.set(s.id, n.id); return n; });
    const L = clip.links.map(l => ({ ...l, id: uid(), from: map.get(l.from), to: map.get(l.to) }));
    shapes.push(...S); links.push(...L);
    sel = new Set(S.map(s => s.id)); selLink = '';
    render(); commit(); updateProps();
  }
  function nudge(dx, dy) {
    if (!sel.size) return;
    for (const s of shapes) if (sel.has(s.id)) { s.x += dx; s.y += dy; }
    render(); commit();
  }
  function reorder(front) {
    const pick = shapes.filter(s => sel.has(s.id)), rest = shapes.filter(s => !sel.has(s.id));
    shapes = front ? rest.concat(pick) : pick.concat(rest);
    render(); commit();
  }
  function applyToSel(fn) {
    for (const s of shapes) if (sel.has(s.id)) fn(s);
    render(); commit(); updateProps();
  }

  // ---------- 文字の編集 ----------
  function startEdit(kind, id) {
    commitEdit();
    let val = '', left, top, wd, ht, fs, align = 'center';
    if (kind === 'shape') {
      const s = byId(id);
      if (!s) return;
      fs = s.fs || 14; val = s.text || '';
      const tb = textBox(s), lh = lineH(fs);
      if (s.type === 'frame') { left = s.x + 4; top = s.y + 4; wd = s.w - 8; ht = lh + 10; align = 'left'; }
      else {
        wd = Math.max(80, tb.maxW + 14); ht = clamp(Math.max(lh * 2 + 10, textLines(s).length * lh + 10), 30, Math.max(30, s.h));
        left = s.x + tb.cx - wd / 2; top = s.y + tb.cy - ht / 2;
      }
    } else {
      const l = linkById(id), pts = l && routePts(l, new Map(shapes.map(s => [s.id, s])));
      if (!pts) return;
      const m = midpoint(pts);
      fs = 13; val = l.label || ''; wd = 170; ht = 34; left = m.x - wd / 2; top = m.y - ht / 2;
    }
    editing = { kind, id };
    const z = view.z;
    Object.assign(editbox.style, { left: (view.x + left * z) + 'px', top: (view.y + top * z) + 'px', width: wd * z + 'px',
      height: ht * z + 'px', fontSize: fs * z + 'px', textAlign: align });
    editbox.dataset.h = ht * z; editbox.dataset.lh = lineH(fs) * z;
    editbox.value = val;
    editbox.hidden = false;
    fitEditPad();
    editbox.focus();
    editbox.select();
    renderUI();
  }
  function fitEditPad() {
    const H = +editbox.dataset.h, lh = +editbox.dataset.lh;
    const n = editbox.value.split('\n').length;
    editbox.style.paddingTop = Math.max(2, (H - n * lh) / 2 - 2) + 'px';
  }
  function growToFit(s) {
    if (s.type === 'frame') return;
    const f = { diamond: 1.7, ellipse: 1.4, parallelogram: 1.05, terminator: 1.05 }[s.type] || 1;
    const need = (textLines(s).length * lineH(s.fs || 14) + 16) * f;
    if (s.h < need) s.h = Math.ceil(need / 10) * 10;
  }
  function commitEdit() {
    if (!editing) return;
    const { kind, id } = editing;
    editing = null;
    const v = editbox.value;
    editbox.hidden = true;
    if (kind === 'shape') {
      const s = byId(id);
      if (s && s.text !== v) { s.text = v; growToFit(s); }
    } else {
      const l = linkById(id);
      if (l) l.label = v;
    }
    render(); commit(); updateProps();
  }
  editbox.addEventListener('input', fitEditPad);
  editbox.addEventListener('blur', commitEdit);
  editbox.addEventListener('keydown', e => {
    if (e.key === 'Escape' || ((e.ctrlKey || e.metaKey) && e.key === 'Enter')) { e.preventDefault(); commitEdit(); }
    e.stopPropagation();
  });

  // ---------- ポインタ操作 ----------
  svg.addEventListener('pointerdown', e => {
    if (e.pointerType === 'mouse' && e.button !== 0 && e.button !== 1) return;
    if (editing) commitEdit();
    try { svg.setPointerCapture(e.pointerId); } catch (_) {}
    ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (ptrs.size === 2) { drag = null; startPinch(); return; }
    if (ptrs.size > 2) return;
    const w = toWorld(e), t = e.target;
    if (e.button === 1 || spaceDown) {
      drag = { k: 'pan', sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: true };
      return;
    }
    const hEl = t.closest('[data-h]'), cEl = t.closest('[data-c]');
    if (tool !== 'select' && !hEl && !cEl) {
      drag = { k: 'create', type: tool, x0: w.x, y0: w.y, x1: w.x, y1: w.y };
      return;
    }
    if (hEl && sel.size === 1) {
      const s = byId([...sel][0]);
      drag = { k: 'resize', h: hEl.dataset.h, id: s.id, o: { x: s.x, y: s.y, w: s.w, h: s.h } };
      return;
    }
    if (cEl && sel.size === 1) {
      drag = { k: 'link', from: [...sel][0], side: cEl.dataset.c, sx: w.x, sy: w.y, x: w.x, y: w.y, hot: '' };
      return;
    }
    const sEl = t.closest('[data-id]');
    if (sEl) {
      const id = sEl.dataset.id;
      if (e.shiftKey) { if (sel.has(id)) sel.delete(id); else sel.add(id); selLink = ''; }
      else if (!sel.has(id)) { sel = new Set([id]); selLink = ''; }
      const ids = new Set(sel);
      for (const sid of sel) {   // 枠を動かすときは、中にある図形も一緒に動かす
        const f = byId(sid);
        if (f && f.type === 'frame') for (const o of shapes) if (inside(o, f)) ids.add(o.id);
      }
      drag = { k: 'move', w0: w, moved: false, ids: [...ids].map(i => { const o = byId(i); return { id: i, x: o.x, y: o.y }; }) };
      renderUI(); updateProps();
      return;
    }
    const lEl = t.closest('[data-lid]');
    if (lEl) { selLink = lEl.dataset.lid; sel = new Set(); renderUI(); updateProps(); return; }
    if (e.shiftKey) { drag = { k: 'marquee', x0: w.x, y0: w.y, x1: w.x, y1: w.y }; return; }
    drag = { k: 'pan', sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, moved: false };
  });

  svg.addEventListener('pointermove', e => {
    if (ptrs.has(e.pointerId)) ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch && ptrs.size === 2) { doPinch(); return; }
    if (!drag) return;
    const w = toWorld(e), d = drag;
    switch (d.k) {
      case 'pan': {
        if (!d.moved && Math.hypot(e.clientX - d.sx, e.clientY - d.sy) > 3) d.moved = true;
        if (d.moved) { view.x = d.vx + (e.clientX - d.sx); view.y = d.vy + (e.clientY - d.sy); applyView(); }
        break;
      }
      case 'move': {
        let dx = w.x - d.w0.x, dy = w.y - d.w0.y;
        if (!d.moved && Math.hypot(dx, dy) * view.z < 3) return;
        d.moved = true;
        if (snap) { const f = d.ids[0]; dx = sn(f.x + dx) - f.x; dy = sn(f.y + dy) - f.y; }
        for (const o of d.ids) { const s = byId(o.id); if (s) { s.x = o.x + dx; s.y = o.y + dy; } }
        render();
        break;
      }
      case 'resize': {
        const s = byId(d.id), o = d.o;
        if (!s) return;
        let x1 = o.x, y1 = o.y, x2 = o.x + o.w, y2 = o.y + o.h;
        if (d.h.includes('w')) x1 = sn(w.x);
        if (d.h.includes('e')) x2 = sn(w.x);
        if (d.h.includes('n')) y1 = sn(w.y);
        if (d.h.includes('s')) y2 = sn(w.y);
        if (x2 - x1 < 24) { if (d.h.includes('w')) x1 = x2 - 24; else x2 = x1 + 24; }
        if (y2 - y1 < 24) { if (d.h.includes('n')) y1 = y2 - 24; else y2 = y1 + 24; }
        s.x = x1; s.y = y1; s.w = x2 - x1; s.h = y2 - y1;
        render();
        break;
      }
      case 'create': case 'marquee': d.x1 = w.x; d.y1 = w.y; renderUI(); break;
      case 'link': {
        d.x = w.x; d.y = w.y;
        const el = document.elementFromPoint(e.clientX, e.clientY), g = el && el.closest && el.closest('[data-id]');
        const t = g && byId(g.dataset.id);
        d.hot = t && t.id !== d.from && t.type !== 'frame' ? t.id : '';
        renderUI();
        break;
      }
    }
  });

  function finishPointer(e) {
    ptrs.delete(e.pointerId);
    if (pinch) { if (ptrs.size < 2) pinch = null; drag = null; return; }
    if (!drag) return;
    const d = drag, w = toWorld(e);
    drag = null;
    switch (d.k) {
      case 'pan': if (!d.moved) { sel = new Set(); selLink = ''; renderUI(); updateProps(); } break;
      case 'move': if (d.moved) commit(); renderUI(); break;
      case 'resize': commit(); renderUI(); break;
      case 'create': finishCreate(d); break;
      case 'link': finishLink(d, e, w); break;
      case 'marquee': {
        const x1 = Math.min(d.x0, d.x1), y1 = Math.min(d.y0, d.y1), x2 = Math.max(d.x0, d.x1), y2 = Math.max(d.y0, d.y1);
        const hit = shapes.filter(s => s.type === 'frame'
          ? s.x >= x1 && s.y >= y1 && s.x + s.w <= x2 && s.y + s.h <= y2
          : s.x < x2 && s.x + s.w > x1 && s.y < y2 && s.y + s.h > y1);
        sel = new Set(hit.map(s => s.id)); selLink = '';
        renderUI(); updateProps();
        break;
      }
    }
    render();
  }
  svg.addEventListener('pointerup', finishPointer);
  svg.addEventListener('pointercancel', finishPointer);

  function finishCreate(d) {
    const def = TYPES[d.type];
    let x = Math.min(d.x0, d.x1), y = Math.min(d.y0, d.y1), w = Math.abs(d.x1 - d.x0), h = Math.abs(d.y1 - d.y0);
    if (w * view.z < 12 && h * view.z < 12) { w = def.w; h = def.h; x = d.x0 - w / 2; y = d.y0 - h / 2; }
    else { w = Math.max(w, 24); h = Math.max(h, 24); }
    if (snap) { x = sn(x); y = sn(y); w = Math.max(20, sn(w)); h = Math.max(20, sn(h)); }
    const s = newShape(d.type, x, y, w, h);
    shapes.push(s);
    sel = new Set([s.id]); selLink = '';
    tool = 'select'; updatePalette();
    render(); commit(); updateProps();
    startEdit('shape', s.id);
  }

  const OPP = { t: 'b', b: 't', l: 'r', r: 'l' };
  function finishLink(d, e, w) {
    if (Math.hypot(w.x - d.sx, w.y - d.sy) * view.z < 10) { renderUI(); return; }
    const el = document.elementFromPoint(e.clientX, e.clientY), g = el && el.closest && el.closest('[data-id]');
    let target = g ? byId(g.dataset.id) : null;
    if (target && target.type === 'frame') target = null;
    if (target && target.id === d.from) { renderUI(); return; }
    let newId = '';
    if (!target) {   // 空きスペースで離した：次の図形を作ってつなぐ
      const def = TYPES.rect, sw = def.w, sh = def.h;
      let x = w.x, y = w.y;
      if (d.side === 'r') y -= sh / 2;
      else if (d.side === 'l') { x -= sw; y -= sh / 2; }
      else if (d.side === 't') { x -= sw / 2; y -= sh; }
      else x -= sw / 2;
      target = newShape('rect', sn(x), sn(y), sw, sh);
      shapes.push(target);
      newId = target.id;
    }
    const tSide = newId ? OPP[d.side] : 'a';
    if (!links.some(l => l.from === d.from && l.to === target.id && l.fSide === d.side && l.tSide === tSide)) {
      links.push({ id: uid(), from: d.from, to: target.id, fSide: d.side, tSide, label: '', style: 'elbow', dash: false, arrow: true });
    }
    sel = new Set([target.id]); selLink = '';
    render(); commit(); updateProps();
    if (newId) startEdit('shape', newId);
  }

  svg.addEventListener('dblclick', e => {
    if (e.target.closest && e.target.closest('[data-h],[data-c]')) return;
    for (const el of document.elementsFromPoint(e.clientX, e.clientY)) {
      const sg = el.closest && el.closest('[data-id]');
      if (sg) { selectOnly(sg.dataset.id); startEdit('shape', sg.dataset.id); return; }
      const lg = el.closest && el.closest('[data-lid]');
      if (lg) { selLink = lg.dataset.lid; sel = new Set(); renderUI(); updateProps(); startEdit('link', selLink); return; }
    }
    const w = toWorld(e), def = TYPES.rect;
    const s = newShape('rect', sn(w.x - def.w / 2), sn(w.y - def.h / 2), def.w, def.h);
    shapes.push(s);
    selectOnly(s.id);
    render(); commit();
    startEdit('shape', s.id);
  });

  svg.addEventListener('wheel', e => {
    e.preventDefault();
    if (editing) commitEdit();
    const r = svg.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * 0.0025));
    else { view.x -= e.deltaX; view.y -= e.deltaY; applyView(); }
  }, { passive: false });

  // ---------- パレット・プロパティ ----------
  function iconEl(type) {
    const s = mk('svg', { width: 28, height: 18, viewBox: '0 0 28 18' });
    if (type === 'select') { mk('path', { d: 'M8,2 L8,15 L11.5,11.5 L14,16 L16,15 L13.5,10.5 L18,10.5 Z', fill: '#333' }, s); return s; }
    if (type === 'text') { const t = mk('text', { x: 14, y: 14, 'text-anchor': 'middle', 'font-size': 14, 'font-weight': 'bold', fill: '#333' }, s); t.textContent = 'T'; return s; }
    const g = mk('g', { transform: 'translate(2 2)' }, s);
    g.appendChild(bodyEl({ type, w: 24, h: 14, fill: type === 'note' ? '#fff3a3' : '#fff', stroke: '#555' }, 1.2));
    return s;
  }
  function buildPalette() {
    const bar = $('palette');
    bar.replaceChildren();
    const add = (type, label) => {
      const b = document.createElement('button');
      b.dataset.type = type;
      b.title = label;
      b.append(iconEl(type));
      const sp = document.createElement('span');
      sp.textContent = label;
      b.append(sp);
      b.onclick = () => { commitEdit(); tool = (type === 'select' || tool === type) ? 'select' : type; updatePalette(); };
      bar.append(b);
    };
    add('select', '選択');
    for (const k of Object.keys(TYPES)) add(k, TYPES[k].label);
  }
  function updatePalette() {
    $('palette').querySelectorAll('button').forEach(b => b.classList.toggle('on', b.dataset.type === tool));
    stage.classList.toggle('tool', tool !== 'select');
  }

  function updateProps() {
    const bar = $('propbar');
    bar.replaceChildren();
    const btn = (text, title, fn, cls) => {
      const b = document.createElement('button');
      b.textContent = text; b.title = title || '';
      if (cls) b.className = cls;
      b.onclick = fn;
      bar.append(b);
      return b;
    };
    const lbl = t => { const s = document.createElement('span'); s.className = 'lbl'; s.textContent = t; bar.append(s); };
    const sep = () => { const s = document.createElement('span'); s.className = 'sep'; bar.append(s); };
    if (selLink && linkById(selLink)) {
      const l = linkById(selLink);
      lbl('線');
      btn(l.style === 'straight' ? '直線' : '直角', '直角／直線を切り替え', () => { l.style = l.style === 'straight' ? 'elbow' : 'straight'; render(); commit(); updateProps(); });
      btn(l.dash ? '点線' : '実線', '実線／点線を切り替え', () => { l.dash = !l.dash; render(); commit(); updateProps(); });
      btn(l.arrow !== false ? '矢印あり' : '矢印なし', '矢印の有無', () => { l.arrow = l.arrow === false; render(); commit(); updateProps(); });
      btn('ラベル', 'ダブルクリックでも編集できます', () => startEdit('link', l.id));
      btn('向きを逆に', '始点と終点を入れ替える', () => {
        [l.from, l.to] = [l.to, l.from]; [l.fSide, l.tSide] = [l.tSide, l.fSide];
        render(); commit(); updateProps();
      });
      sep();
      btn('削除', 'Delete', deleteSelection, 'danger');
    } else if (sel.size) {
      const one = sel.size === 1 ? byId([...sel][0]) : null;
      const first = shapes.find(s => sel.has(s.id));
      lbl('塗り');
      FILLS.forEach(c => {
        const b = btn('', c === 'none' ? '塗りなし' : c, () => applyToSel(s => { s.fill = c; }), 'swatch' + (c === 'none' ? ' none' : '') + (first && first.fill === c ? ' on' : ''));
        if (c !== 'none') b.style.background = c;
      });
      lbl('線・枠');
      STROKES.forEach(c => {
        const b = btn('', c, () => applyToSel(s => { s.stroke = c; }), 'swatch ring' + (first && first.stroke === c ? ' on' : ''));
        b.style.borderColor = c + ''; b.style.setProperty('border-color', c, 'important');
      });
      lbl('文字');
      const sel2 = document.createElement('select');
      SIZES.forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + 'px'; o.selected = first && (first.fs || 14) === n; sel2.append(o); });
      sel2.onchange = () => applyToSel(s => { s.fs = +sel2.value; growToFit(s); });
      bar.append(sel2);
      sep();
      if (one) btn('文字を編集', 'Enter / ダブルクリック', () => startEdit('shape', one.id));
      btn('前面へ', '', () => reorder(true));
      btn('背面へ', '', () => reorder(false));
      btn('複製', 'Ctrl+D', () => { if (copySel()) paste(); });
      btn('削除', 'Delete', deleteSelection, 'danger');
    } else { bar.hidden = true; return; }
    bar.hidden = false;
  }

  // ---------- 書き出し ----------
  function buildSvg(S, L, pad = 24) {
    const b = bboxOf(S, L) || { x: 0, y: 0, w: 400, h: 300 };
    const x = b.x - pad, y = b.y - pad, w = b.w + pad * 2, h = b.h + pad * 2;
    const root = document.createElementNS(NS, 'svg');
    root.setAttribute('xmlns', NS);
    root.setAttribute('viewBox', `${x} ${y} ${w} ${h}`);
    root.setAttribute('width', Math.ceil(w)); root.setAttribute('height', Math.ceil(h));
    root.appendChild(svg.querySelector('defs').cloneNode(true));
    mk('rect', { x, y, width: w, height: h, fill: '#ffffff' }, root);
    const fr = mk('g', {}, root), lk = mk('g', {}, root), sh = mk('g', {}, root);
    drawInto(fr, lk, sh, S, L, false);
    return { root, w, h };
  }
  const fileBase = () => (titleIn.value.trim() || 'board').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 60);
  function download(blob, name) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }
  function exportSvg() {
    commitEdit();
    if (!shapes.length) return msg('図形がありません', true);
    const { root } = buildSvg(shapes, links);
    download(new Blob([new XMLSerializer().serializeToString(root)], { type: 'image/svg+xml;charset=utf-8' }), fileBase() + '.svg');
  }
  function exportPng() {
    commitEdit();
    if (!shapes.length) return msg('図形がありません', true);
    const { root, w, h } = buildSvg(shapes, links);
    const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(root)], { type: 'image/svg+xml;charset=utf-8' }));
    const img = new Image();
    img.onload = () => {
      const sc = Math.min(2, 4000 / Math.max(w, h));
      const cv = document.createElement('canvas');
      cv.width = Math.round(w * sc); cv.height = Math.round(h * sc);
      cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
      cv.toBlob(b => { URL.revokeObjectURL(url); if (b) download(b, fileBase() + '.png'); else msg('PNGの作成に失敗しました', true); }, 'image/png');
    };
    img.onerror = () => { URL.revokeObjectURL(url); msg('PNGの作成に失敗しました', true); };
    img.src = url;
  }

  // ---------- 保存・読み込み ----------
  const urlFor = id => PERMA_BASE ? PERMA_BASE + id : ep + '?id=' + id;
  const absUrl = id => new URL(id ? urlFor(id) : (PERMA_BASE || ep), location.href).href;
  function idFromLocation() {
    const q = new URLSearchParams(location.search).get('id');
    if (q && NAME_RE.test(q)) return q;
    if (PERMA_BASE) {
      const bp = new URL(PERMA_BASE, location.href).pathname;
      if (location.pathname.startsWith(bp) && NAME_RE.test(location.pathname.slice(bp.length))) return location.pathname.slice(bp.length);
    }
    return '';
  }
  function syncUrl(id, how) {
    try {
      const target = absUrl(id);
      if (new URL(target).origin !== location.origin || target === location.href) return;
      history[how === 'replace' ? 'replaceState' : 'pushState']({ id }, '', target);
    } catch (e) { /* アドレスバーを変えられなくても動作に影響しない */ }
  }
  async function copyLink() {
    if (!currentId) return msg('先に保存してください', true);
    const url = absUrl(currentId);
    try { await navigator.clipboard.writeText(url); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = url; ta.style.cssText = 'position:fixed;opacity:0';
      document.body.append(ta); ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (e2) { /* 下で案内 */ }
      ta.remove();
      if (!ok) { prompt('このリンクをコピーしてください', url); return; }
    }
    msg('このボードのリンクをコピーしました：' + url);
  }

  function updateButtons() {
    $('delBtn').disabled = !currentId;
    $('histBtn').disabled = !currentId;
    $('copyLink').disabled = !currentId;
  }

  function setBoard(b, title) {
    shapes = Array.isArray(b.shapes) ? b.shapes : [];
    links = Array.isArray(b.links) ? b.links : [];
    view = b.view && b.view.z ? { x: b.view.x, y: b.view.y, z: b.view.z } : { x: 60, y: 60, z: 1 };
    titleIn.value = title || '';
    document.title = (title ? title + ' - ' : '') + 'Board';
    sel = new Set(); selLink = ''; tool = 'select';
    editing = null; editbox.hidden = true; drag = null;
    resetHistory(); markDirty(false);
    updatePalette(); updateButtons(); applyView(); render(); updateProps();
  }

  async function save() {
    commitEdit();
    if (saving) return false;
    if (!currentId && !shapes.length) { msg('図形がないボードは保存できません', true); return false; }
    saving = true;
    try {
      const r = await fetch(ep + '?action=save', {
        method: 'POST',
        body: new URLSearchParams({
          id: currentId,
          title: titleIn.value.trim(),
          data64: toBase64(JSON.stringify({ v: 1, shapes, links, view })),
        }),
      });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      currentId = j.id;
      titleIn.value = j.title;
      document.title = j.title + ' - Board';
      markDirty(false);
      syncUrl(j.id, 'replace');
      updateButtons();
      msg(j.revisions > 1 ? `保存しました：${j.title}（履歴 ${j.revisions}件）` : `保存しました：${j.title}`);
      await refresh();
      return true;
    } catch (e) {
      msg('保存に失敗しました：' + e.message, true);
      return false;
    } finally { saving = false; }
  }

  async function load(id, opts = {}) {
    if (!id) return false;
    if (!opts.force && id === currentId && !dirty) return true;
    if (dirty && !confirm('未保存の変更があります。破棄して開きますか？')) return false;
    try {
      const r = await fetch(ep + '?action=load&id=' + encodeURIComponent(id), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      currentId = j.id;
      setBoard(j.board, j.title);
      if (!(j.board.view && j.board.view.z)) fit();
      renderList();
      msg(`開きました：${j.title}`);
      if (window.innerWidth <= 720) document.body.classList.add('side-closed');
      if (opts.url !== 'none') syncUrl(j.id, opts.url || 'push');
      return true;
    } catch (e) {
      msg(e.message === 'not found' ? '指定されたボードは見つかりません（削除された可能性があります）' : '読み込みに失敗しました：' + e.message, true);
      return false;
    }
  }

  function newBoard(opts = {}) {
    if (!opts.force && dirty && !confirm('未保存の変更があります。破棄して新規作成しますか？')) return;
    currentId = '';
    setBoard({ shapes: [], links: [], view: { x: 60, y: 60, z: 1 } }, '');
    renderList();
    if (!opts.noUrl) syncUrl('', 'push');
    msg('新しいボードです');
  }

  async function deleteBoard() {
    if (!currentId) return;
    const id = currentId, title = titleIn.value || id;
    if (!confirm(`「${title}」を削除しますか？\n\nこのボードへのリンクは「見つかりません」になります。`)) return;
    try {
      const r = await fetch(ep + '?action=delete', { method: 'POST', body: new URLSearchParams({ id }) });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      markDirty(false);
      await refresh();
      newBoard({ force: true });
      msg(`削除しました：${title}`);
    } catch (e) { msg('削除に失敗しました：' + e.message, true); }
  }

  // ---------- サイドバー ----------
  const byTitle = (a, b) => a.title.localeCompare(b.title, 'ja', { numeric: true });
  function renderList() {
    const q = filterEl.value.trim().toLowerCase();
    listEl.replaceChildren();
    const items = docs.filter(d => d.title.toLowerCase().includes(q));
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = docs.length ? '該当するボードがありません' : '保存済みのボードはありません';
      listEl.append(li);
      return;
    }
    for (const d of (q ? items.sort(byTitle) : items)) {
      const li = document.createElement('li');
      const b = document.createElement('button');
      b.className = 'doc' + (d.id === currentId ? ' active' : '');
      b.dataset.id = d.id;
      b.innerHTML = '<span class="t"></span><span class="d"></span>';
      b.querySelector('.t').textContent = d.title;
      b.querySelector('.d').textContent = d.updated;
      li.append(b);
      listEl.append(li);
    }
  }
  async function refresh() {
    const r = await fetch(ep + '?action=list', { cache: 'no-store' });
    const list = await readJson(r);
    if (!r.ok) throw new Error(list.error || r.status);
    docs = list;
    renderList();
  }

  // ---------- 更新履歴 ----------
  const histDlg = $('histdlg');
  let histRevs = [], histSel = null;
  async function openHistory() {
    if (!currentId) return;
    try {
      const r = await fetch(ep + '?action=history&id=' + encodeURIComponent(currentId), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      histRevs = j.revisions; histSel = null;
      $('histtitle').textContent = `更新履歴：${titleIn.value || currentId}`;
      $('histview').replaceChildren(); $('histinfo').textContent = '';
      $('histrestore').disabled = true;
      histDlg.hidden = false;
      renderHistory();
      if (histRevs.length) await showRevision(histRevs[0].rev);
    } catch (e) { msg('履歴の取得に失敗しました：' + e.message, true); }
  }
  function closeHistory() { histDlg.hidden = true; histSel = null; }
  function renderHistory() {
    const ul = $('histlist');
    ul.replaceChildren();
    if (!histRevs.length) {
      const li = document.createElement('li');
      li.className = 'empty'; li.textContent = '履歴はまだありません';
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
      if (i === 0) { const tag = document.createElement('span'); tag.className = 'cur-tag'; tag.textContent = '現在'; b.querySelector('.t').append(tag); }
      b.querySelector('.d').textContent = [v.by, v.title].filter(Boolean).join(' ・ ');
      li.append(b);
      ul.append(li);
    });
  }
  async function showRevision(rev) {
    try {
      const r = await fetch(ep + '?action=revision&id=' + encodeURIComponent(currentId) + '&rev=' + encodeURIComponent(rev), { cache: 'no-store' });
      const j = await readJson(r);
      if (!r.ok || !j.ok) throw new Error(j.error || r.status);
      const isLatest = histRevs.length > 0 && histRevs[0].rev === rev;
      histSel = { rev, at: j.at, board: j.board, title: j.title, isLatest };
      const { root } = buildSvg(j.board.shapes || [], j.board.links || []);
      root.removeAttribute('width'); root.removeAttribute('height');
      $('histview').replaceChildren(root);
      $('histinfo').textContent = [j.at, j.by].filter(Boolean).join(' ・ ') + (isLatest ? '（現在の版）' : '');
      $('histrestore').disabled = isLatest;
      renderHistory();
    } catch (e) { $('histinfo').textContent = '版の取得に失敗しました：' + e.message; }
  }
  function restoreRevision() {
    if (!histSel || histSel.isLatest) return;
    if (dirty && !confirm('未保存の変更があります。この版の内容で置き換えますか？')) return;
    const { at, board, title } = histSel;
    closeHistory();
    const id = currentId;
    setBoard(board, title);
    currentId = id;
    updateButtons();
    markDirty(true);
    msg(`${at} の版を読み込みました。保存すると、新しい版として記録されます`);
  }

  // ---------- アプリメニュー（右上のボタン。右からスライドして出る） ----------
  const appBtn = $('appmenuBtn'), appMenu = $('appmenu'), appBackdrop = $('appmenu-backdrop');
  const appFocusable = () => Array.from(appMenu.querySelectorAll('a[href], button'));
  function setAppMenu(open) {
    if (open) commitEdit();
    appMenu.classList.toggle('open', open);
    appBackdrop.classList.toggle('open', open);
    appBtn.setAttribute('aria-expanded', String(open));
    appBtn.setAttribute('aria-label', open ? 'アプリメニューを閉じる' : 'アプリメニューを開く');
    if (open) appFocusable()[1].focus(); else appBtn.focus();
  }
  appBtn.addEventListener('click', () => setAppMenu(!appMenu.classList.contains('open')));
  $('appmenuClose').addEventListener('click', () => setAppMenu(false));
  appBackdrop.addEventListener('click', () => setAppMenu(false));
  document.addEventListener('keydown', e => {
    if (!appMenu.classList.contains('open')) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setAppMenu(false); return; }
    if (e.key === 'Tab') {   // メニューの中だけで Tab を回す
      const f = appFocusable(), first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }, true);

  // ---------- イベント ----------
  $('save').onclick = save;
  $('new').onclick = () => newBoard();
  $('delBtn').onclick = deleteBoard;
  $('histBtn').onclick = openHistory;
  $('histclose').onclick = closeHistory;
  $('histrestore').onclick = restoreRevision;
  $('copyLink').onclick = copyLink;
  $('undoBtn').onclick = undo;
  $('redoBtn').onclick = redo;
  $('expPng').onclick = exportPng;
  $('expSvg').onclick = exportSvg;
  $('fitBtn').onclick = fit;
  $('zoomIn').onclick = () => { const r = svg.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 1.25); };
  $('zoomOut').onclick = () => { const r = svg.getBoundingClientRect(); zoomAt(r.width / 2, r.height / 2, 0.8); };
  $('snapBtn').onclick = () => { snap = !snap; $('snapBtn').classList.toggle('on', snap); msg(snap ? 'グリッドに吸着します' : '吸着をやめました'); };
  $('menu').onclick = () => document.body.classList.toggle('side-closed');
  filterEl.addEventListener('input', renderList);
  titleIn.addEventListener('input', () => { markDirty(); document.title = (titleIn.value ? titleIn.value + ' - ' : '') + 'Board'; });
  titleIn.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); titleIn.blur(); } });

  listEl.addEventListener('click', e => {
    const b = e.target.closest('button[data-id]');
    if (b) load(b.dataset.id);
  });
  histDlg.addEventListener('click', e => { if (e.target === histDlg) closeHistory(); });
  $('histlist').addEventListener('click', e => {
    const b = e.target.closest('button[data-rev]');
    if (b) showRevision(b.dataset.rev);
  });

  const isTyping = t => t && t.matches && t.matches('input,textarea,select');
  document.addEventListener('keydown', e => {
    if (appMenu.classList.contains('open')) return;   // メニューを開いている間は、ボードのショートカットを無効にする
    if (isTyping(e.target)) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); save(); }
      return;
    }
    const mod = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
    if (mod && k === 's') { e.preventDefault(); save(); return; }
    if (!histDlg.hidden) { if (e.key === 'Escape') closeHistory(); return; }
    if (mod && k === 'z') { e.preventDefault(); e.shiftKey ? redo() : undo(); return; }
    if (mod && k === 'y') { e.preventDefault(); redo(); return; }
    if (mod && k === 'c') { if (copySel()) e.preventDefault(); return; }
    if (mod && k === 'v') { if (clip) { e.preventDefault(); paste(); } return; }
    if (mod && k === 'd') { e.preventDefault(); if (copySel()) paste(); return; }
    if (mod && k === 'a') { e.preventDefault(); sel = new Set(shapes.map(s => s.id)); selLink = ''; renderUI(); updateProps(); return; }
    if (e.key === ' ') { if (!spaceDown) { spaceDown = true; stage.classList.add('panning'); } e.preventDefault(); return; }
    if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); deleteSelection(); return; }
    if (e.key === 'Escape') { tool = 'select'; updatePalette(); sel = new Set(); selLink = ''; renderUI(); updateProps(); return; }
    if ((e.key === 'Enter' || e.key === 'F2') && sel.size === 1) { e.preventDefault(); startEdit('shape', [...sel][0]); return; }
    if (e.key === 'Enter' && selLink) { e.preventDefault(); startEdit('link', selLink); return; }
    const step = e.shiftKey ? 1 : 10;
    if (e.key === 'ArrowLeft')  { e.preventDefault(); nudge(-step, 0); }
    if (e.key === 'ArrowRight') { e.preventDefault(); nudge(step, 0); }
    if (e.key === 'ArrowUp')    { e.preventDefault(); nudge(0, -step); }
    if (e.key === 'ArrowDown')  { e.preventDefault(); nudge(0, step); }
  });
  document.addEventListener('keyup', e => { if (e.key === ' ') { spaceDown = false; stage.classList.remove('panning'); } });

  window.addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  window.addEventListener('resize', () => { if (editing) commitEdit(); });
  window.addEventListener('popstate', async () => {
    const id = idFromLocation();
    let ok;
    if (id) ok = await load(id, { url: 'none' });
    else if (!currentId) ok = true;
    else if (dirty && !confirm('未保存の変更があります。破棄して新規作成しますか？')) ok = false;
    else { newBoard({ force: true, noUrl: true }); ok = true; }
    if (!ok) syncUrl(currentId, 'push');
  });

  // ---------- 起動 ----------
  if (window.innerWidth <= 720) document.body.classList.add('side-closed');
  buildPalette();
  updatePalette();
  setBoard({ shapes: [], links: [], view: { x: 60, y: 60, z: 1 } }, '');
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
  when 'list', 'load', 'save', 'delete', 'history', 'revision'
    email = current_email(cgi)
    return send_json(cgi, { ok: false, error: 'login required' }, 'AUTH_REQUIRED') unless email

    case action
    when 'list'     then handle_list(cgi)
    when 'load'     then handle_load(cgi)
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
  warn "[board] #{e.class}: #{e.message}"
  begin
    send_html(CGI.new, html_message('エラーが発生しました', '時間をおいて再度お試しください。'), 'SERVER_ERROR')
  rescue StandardError
    nil
  end
end
