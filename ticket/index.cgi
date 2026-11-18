#!/usr/local/bin/ruby2.6
# coding: utf-8
#
# Ticket（Jira風チケット管理）— Googleアカウントログイン付き
# Papyru（WYSIWYG エディタ）と同じ作り・同じ設置方法の、ロリポップ！向け Ruby CGI。標準ライブラリのみ使用。
#
# 設置:
#   1. index.cgi と config.json を同じディレクトリに置く（例: public_html/ticket/）
#   2. パーミッション: index.cgi は 700 / config.json は 600 / ディレクトリは 705
#   3. 1行目のshebangは契約サーバーに合わせて変更
#   4. Google Cloud Console で OAuth クライアント（ウェブ アプリケーション）を作成し、
#      承認済みのリダイレクト URI に config.json の redirect_uri を登録
#   5. https://（ドメイン）/ticket/index.cgi を開く
#
ENV['TZ'] ||= 'Asia/Tokyo'
require 'cgi'
require 'json'
require 'net/http'
require 'openssl'
require 'securerandom'
require 'uri'

BASE_DIR       = File.expand_path(File.dirname(__FILE__))
DATA_DIR       = File.join(BASE_DIR, 'data')
ISSUE_DIR      = File.join(DATA_DIR, 'issues')     # チケット: <KEY>-<番号>.json
PROJECT_DIR    = File.join(DATA_DIR, 'projects')   # プロジェクト: <KEY>.json
TRASH_DIR      = File.join(DATA_DIR, 'trash')
LOCK_PATH      = File.join(DATA_DIR, '.lock')
CONFIG_PATH    = File.join(BASE_DIR, 'config.json')
NAME_RE        = /\A[A-Za-z0-9_\-]{1,50}\z/
KEY_RE         = /\A[A-Z][A-Z0-9]{1,9}\z/
MAX_BYTES      = 200_000      # 説明・コメント1件あたりの上限
MAX_HISTORY    = 200          # 1チケットに残す更新履歴の数
SESSION_TTL    = 12 * 3600
STATE_TTL      = 600
SESSION_COOKIE = 'ticket_session'
STATE_COOKIE   = 'ticket_oauth_state'
RETURN_COOKIE  = 'ticket_return'   # ログイン後に戻るチケットのID

STATUSES   = [%w[todo 未着手], %w[doing 進行中], %w[review レビュー], %w[done 完了]].freeze
TYPES      = [%w[task タスク #4bade8], %w[bug バグ #e5493a], %w[story ストーリー #63ba3c],
              %w[epic エピック #904ee2]].freeze
PRIORITIES = [%w[highest 最高 #cd1317 ▲▲], %w[high 高 #e5493a ▲], %w[medium 中 #e97f33 ■],
              %w[low 低 #2a8735 ▼], %w[lowest 最低 #57a55a ▼▼]].freeze

# ---------- 設定 ----------

def config
  @config ||= JSON.parse(File.read(CONFIG_PATH, encoding: 'utf-8'))
end

# 署名鍵が短い／未設定だとセッションを偽造されるため、設定の不備は起動時に弾く
def config_problem
  c = config
  return 'google_client_id / google_client_secret / redirect_uri を config.json に設定してください。' if
    %w[google_client_id google_client_secret redirect_uri].any? { |k| c[k].to_s.strip.empty? }
  return 'session_secret は32文字以上のランダムな文字列にしてください。' if c['session_secret'].to_s.length < 32
  nil
rescue Errno::ENOENT, JSON::ParserError
  'config.json が見つからないか、JSONとして読めません。'
end

def allowed_emails
  Array(config['allowed_emails']).map { |e| e.to_s.strip.downcase }.reject(&:empty?)
end

def allowed?(email)
  return false if email.to_s.empty?
  allowed_emails.include?(email.downcase)
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

# パーマリンクの土台URL（config.json の permalink_base。例: https://kawanoyuki.com/ticket/）
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
def js_json(value)
  JSON.generate(value).gsub('<') { '<' }.gsub(" ") { ' ' }.gsub(" ") { ' ' }
end

def js_literal(value)
  js_json([value.to_s])[1..-2]
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
  opts = { 'type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store' }
  opts['status'] = status if status
  opts['cookie'] = cookies if cookies
  cgi.out(opts) { JSON.generate(obj) }
end

def send_html(cgi, body, status = nil)
  opts = { 'type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store' }
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
  # ログイン後に、開こうとしていたチケットへ戻る
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

# ---------- ファイル保存 ----------

def valid_name?(name)
  name.to_s.match?(NAME_RE)
end

def ensure_dirs
  [DATA_DIR, ISSUE_DIR, PROJECT_DIR, TRASH_DIR].each do |d|
    Dir.mkdir(d, 0o700) unless Dir.exist?(d)
  end
end

# 採番・更新の取り合いを防ぐ排他ロック
def with_lock
  ensure_dirs
  File.open(LOCK_PATH, File::RDWR | File::CREAT, 0o600) do |f|
    f.flock(File::LOCK_EX)
    yield
  end
end

def read_json_file(path)
  return nil unless File.file?(path)
  JSON.parse(File.read(path, encoding: 'utf-8'))
rescue JSON::ParserError
  nil
end

# 書きかけのファイルが残らないよう、一時ファイルに書いてから置き換える
def write_json_file(path, obj)
  tmp = "#{path}.#{$$}.tmp"
  File.write(tmp, JSON.generate(obj))
  File.chmod(0o600, tmp)
  File.rename(tmp, path)
end

def project_path(key)
  File.join(PROJECT_DIR, "#{key}.json")
end

def issue_path(id)
  File.join(ISSUE_DIR, "#{id}.json")
end

def read_project(key)
  key.to_s.match?(KEY_RE) ? read_json_file(project_path(key)) : nil
end

def read_issue(id)
  valid_name?(id) ? read_json_file(issue_path(id)) : nil
end

def all_projects
  Dir.glob(File.join(PROJECT_DIR, '*.json')).map { |f| read_json_file(f) }.compact
     .select { |p| p['key'].to_s.match?(KEY_RE) }.sort_by { |p| p['key'] }
end

def all_issues
  Dir.glob(File.join(ISSUE_DIR, '*.json')).map { |f| read_json_file(f) }.compact
     .select { |i| valid_name?(i['id']) }
end

def clean_text(raw, max)
  t = raw.to_s.dup.force_encoding('UTF-8').scrub.gsub(/[[:cntrl:]]+/, ' ').strip
  t[0, max].to_s.strip
end

# 本文系（説明・コメント）。改行は残す
def clean_body(raw)
  raw.to_s.dup.force_encoding('UTF-8').scrub.gsub("\r\n", "\n").gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F]/, '')
end

def parse_labels(raw)
  raw.to_s.split(/[,、\s]+/).map { |x| clean_text(x, 30) }.reject(&:empty?).uniq.first(20)
end

def pick(list, value, default)
  list.map(&:first).include?(value.to_s) ? value.to_s : default
end

def fmt_time(t)
  Time.at(t.to_i).strftime('%Y-%m-%d %H:%M')
end

def parent_of(id)
  (read_issue(id) || {})['parent'].to_s
end

# pid が id 自身、または id の子孫なら true（親に指定すると循環してしまう）
def descendant_or_self?(pid, id)
  cur = pid
  200.times do
    return true if cur == id
    cur = parent_of(cur)
    return false if cur.empty?
  end
  true
end

def issue_summary(i)
  { id: i['id'], project: i['project'], num: i['num'].to_i, title: i['title'].to_s, type: i['type'],
    status: i['status'], priority: i['priority'], assignee: i['assignee'].to_s, parent: i['parent'].to_s,
    labels: Array(i['labels']), updated: fmt_time(i['updated']) }
end

def issue_full(i)
  issue_summary(i).merge(
    description: i['description'].to_s, reporter: i['reporter'].to_s, created: fmt_time(i['created']),
    comments: Array(i['comments']).map { |c| { by: c['by'].to_s, at: fmt_time(c['at']), body: c['body'].to_s } }
  )
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

# 本文はbase64で受け取る（記号やタグを含むPOSTがWAF等に弾かれるのを避けるため）。平文のパラメータも受け付ける。
def posted_text(cgi, name)
  params = cgi.params
  if params.key?("#{name}64")
    clean_body(cgi["#{name}64"].to_s.unpack1('m'))
  elsif params.key?(name)
    clean_body(cgi[name])
  end
end

# ---------- プロジェクト ----------

def handle_project_save(cgi, email)
  return unless post_only(cgi)

  key  = cgi['key'].to_s.strip.upcase
  name = clean_text(cgi['name'], 100)
  desc = clean_text(cgi['desc'], 300)
  create = cgi['create'].to_s == '1'
  unless key.match?(KEY_RE)
    return send_json(cgi, { ok: false, error: 'キーは英大文字で始まる2〜10文字の英数字にしてください' }, 'BAD_REQUEST')
  end
  return send_json(cgi, { ok: false, error: 'プロジェクト名は必須です' }, 'BAD_REQUEST') if name.empty?

  res = with_lock do
    pj = read_project(key)
    if create && pj
      [{ ok: false, error: 'そのキーは既に使われています' }, 'BAD_REQUEST']
    elsif !create && !pj
      [{ ok: false, error: 'not found' }, 'NOT_FOUND']
    else
      pj ||= { 'key' => key, 'counter' => 0, 'created' => Time.now.to_i, 'by' => email }
      pj['name'] = name
      pj['desc'] = desc
      write_json_file(project_path(key), pj)
      [{ ok: true, key: key }, nil]
    end
  end
  send_json(cgi, res[0], res[1])
end

# ---------- チケット API ----------

def handle_list(cgi, email)
  issues = all_issues
  counts = Hash.new { |h, k| h[k] = [0, 0] }
  issues.each do |i|
    counts[i['project']][1] += 1
    counts[i['project']][0] += 1 unless i['status'] == 'done'
  end
  projects = all_projects.map do |p|
    { key: p['key'], name: p['name'].to_s, desc: p['desc'].to_s, open: counts[p['key']][0], total: counts[p['key']][1] }
  end
  send_json(cgi, { ok: true, me: email, projects: projects, users: allowed_emails,
                   issues: issues.map { |i| issue_summary(i) } })
end

def handle_load(cgi)
  issue = read_issue(cgi['id'].to_s)
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless issue
  send_json(cgi, { ok: true, issue: issue_full(issue) })
end

def handle_history(cgi)
  issue = read_issue(cgi['id'].to_s)
  return send_json(cgi, { ok: false, error: 'not found' }, 'NOT_FOUND') unless issue
  list = Array(issue['history']).reverse.map do |h|
    { by: h['by'].to_s, at: fmt_time(h['at']), note: h['note'].to_s, changes: Array(h['changes']) }
  end
  send_json(cgi, { ok: true, id: issue['id'], history: list })
end

# 新規作成（id が空）または更新（指定された項目だけ変更）
def handle_save(cgi, email)
  return unless post_only(cgi)

  params    = cgi.params
  id        = cgi['id'].to_s.strip
  new_issue = id.empty?
  desc      = posted_text(cgi, 'desc')
  if desc && desc.bytesize > MAX_BYTES
    return send_json(cgi, { ok: false, error: 'too large' }, 'BAD_REQUEST')
  end

  res = with_lock do
    now = Time.now.to_i
    if new_issue
      pj = read_project(cgi['project'].to_s.strip)
      next [{ ok: false, error: 'プロジェクトが見つかりません' }, 'BAD_REQUEST'] unless pj
      issue = { 'project' => pj['key'], 'title' => '', 'description' => '', 'type' => 'task', 'status' => 'todo',
                'priority' => 'medium', 'assignee' => '', 'reporter' => email, 'labels' => [], 'parent' => '',
                'created' => now, 'updated' => now, 'comments' => [], 'history' => [] }
    else
      issue = read_issue(id)
      next [{ ok: false, error: 'not found' }, 'NOT_FOUND'] unless issue
    end

    changes = []
    set = lambda do |f, v|
      old = issue[f]
      next if old == v
      big = f == 'description'   # 説明は長いので、変更の事実だけ履歴に残す
      changes << { 'f' => f, 'from' => (big ? nil : old), 'to' => (big ? nil : v) }
      issue[f] = v
    end

    if params.key?('title') || new_issue
      t = clean_text(cgi['title'], 200)
      next [{ ok: false, error: 'タイトルは必須です' }, 'BAD_REQUEST'] if t.empty?
      set.call('title', t)
    end
    set.call('description', desc) if desc
    set.call('type', pick(TYPES, cgi['type'], issue['type'])) if params.key?('type')
    set.call('status', pick(STATUSES, cgi['status'], issue['status'])) if params.key?('status')
    set.call('priority', pick(PRIORITIES, cgi['priority'], issue['priority'])) if params.key?('priority')
    if params.key?('assignee')
      a = cgi['assignee'].to_s.strip.downcase
      next [{ ok: false, error: '担当者に指定できないユーザーです' }, 'BAD_REQUEST'] unless a.empty? || allowed?(a)
      set.call('assignee', a)
    end
    set.call('labels', parse_labels(cgi['labels'])) if params.key?('labels')
    if params.key?('parent')
      pid = cgi['parent'].to_s.strip
      unless pid.empty?
        par = read_issue(pid)
        next [{ ok: false, error: '親チケットが見つかりません' }, 'BAD_REQUEST'] unless par && par['project'] == issue['project']
        if !new_issue && descendant_or_self?(pid, issue['id'])
          next [{ ok: false, error: '自分自身や子孫は親にできません' }, 'BAD_REQUEST']
        end
      end
      set.call('parent', pid)
    end

    if new_issue
      pj['counter'] = pj['counter'].to_i + 1
      pj['counter'] += 1 while File.exist?(issue_path("#{pj['key']}-#{pj['counter']}"))
      issue['id']  = "#{pj['key']}-#{pj['counter']}"
      issue['num'] = pj['counter']
      issue['history'] << { 'by' => email, 'at' => now, 'note' => '作成', 'changes' => [] }
      write_json_file(project_path(pj['key']), pj)
    elsif changes.empty?
      next [{ ok: true, issue: issue_full(issue), unchanged: true }, nil]
    else
      issue['updated'] = now
      issue['history'] << { 'by' => email, 'at' => now, 'note' => '', 'changes' => changes }
      issue['history'] = issue['history'].last(MAX_HISTORY)
    end
    write_json_file(issue_path(issue['id']), issue)
    [{ ok: true, issue: issue_full(issue), created: new_issue }, nil]
  end
  send_json(cgi, res[0], res[1])
end

def handle_comment(cgi, email)
  return unless post_only(cgi)

  body = (posted_text(cgi, 'body') || '').strip
  return send_json(cgi, { ok: false, error: 'コメントが空です' }, 'BAD_REQUEST') if body.empty?
  return send_json(cgi, { ok: false, error: 'too large' }, 'BAD_REQUEST') if body.bytesize > MAX_BYTES

  res = with_lock do
    issue = read_issue(cgi['id'].to_s)
    next [{ ok: false, error: 'not found' }, 'NOT_FOUND'] unless issue
    now = Time.now.to_i
    issue['comments'] = Array(issue['comments']) << { 'by' => email, 'at' => now, 'body' => body }
    issue['updated'] = now
    write_json_file(issue_path(issue['id']), issue)
    [{ ok: true, issue: issue_full(issue) }, nil]
  end
  send_json(cgi, res[0], res[1])
end

# チケットを削除する。実ファイルは data/trash/ へ移すだけで、完全には消さない。
# 子チケットは削除したチケットの親（無ければ最上位）へ繰り上げる。
def handle_delete(cgi)
  return unless post_only(cgi)

  res = with_lock do
    id = cgi['id'].to_s
    issue = read_issue(id)
    next [{ ok: false, error: 'not found' }, 'NOT_FOUND'] unless issue

    grand = issue['parent'].to_s
    children = all_issues.select { |i| i['parent'].to_s == id }
    children.each do |c|
      c['parent'] = grand
      write_json_file(issue_path(c['id']), c)
    end
    File.rename(issue_path(id), File.join(TRASH_DIR, "#{Time.now.strftime('%Y%m%d%H%M%S')}_#{id}.json"))
    [{ ok: true, id: id, promoted: children.size }, nil]
  end
  send_json(cgi, res[0], res[1])
end

# ---------- 画面 ----------

LOGIN_PAGE = <<~'HTML'
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ticket - ログイン</title>
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
  <h1>Ticket</h1>
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
<title>Ticket</title>
<style>
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html, body { height: 100%; }
  body { margin: 0; display: flex; flex-direction: column; font-family: -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; background: #f2f3f5; color: #222; }

  header { flex: none; background: #2f3640; color: #fff; padding: 8px 14px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
  header .user { font-weight: normal; font-size: 13px; }
  header a { color: #fff; }
  header .menu { font: inherit; background: transparent; color: #fff; border: 1px solid #667; border-radius: 4px; padding: 2px 8px; cursor: pointer; margin-right: 6px; }
  #status { font-weight: normal; font-size: 13px; color: #cfe0ff; }
  #status.err { color: #ffb4ab; }

  .layout { flex: 1; min-height: 0; display: flex; position: relative; }

  /* サイドバー（チケット一覧） */
  #sidebar { flex: none; width: 280px; background: #fff; border-right: 1px solid #ddd; display: flex; flex-direction: column; min-height: 0; }
  body.side-closed #sidebar { display: none; }
  .side-head { padding: 10px; border-bottom: 1px solid #eee; display: flex; flex-direction: column; gap: 6px; }
  .side-head .row { display: flex; gap: 6px; }
  .side-head select, .side-head input { flex: 1; min-width: 0; font: inherit; font-size: 14px; padding: 6px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fff; }
  .side-head button { font: inherit; font-size: 14px; padding: 4px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }
  #doclist { list-style: none; margin: 0; padding: 0; overflow-y: auto; flex: 1; }
  #doclist li { display: flex; align-items: stretch; }
  #doclist li button.doc { flex: 1; min-width: 0; display: block; text-align: left; font: inherit; background: transparent; border: 0; border-bottom: 1px solid #f0f0f0; padding: 8px 10px; cursor: pointer; }
  #doclist li button.doc:hover { background: #f3f6fd; }
  #doclist li button.doc.active { background: #e3ecff; }
  #doclist li .tog, #doclist li .tog-space { flex: none; width: 26px; padding: 0; border: 0; border-bottom: 1px solid #f0f0f0; background: transparent; color: #666; font-size: 11px; }
  #doclist li .tog { cursor: pointer; }
  #doclist li .tog:hover { background: #f3f6fd; }
  .doc .t { display: block; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .doc .d { display: block; font-size: 11px; color: #888; font-weight: normal; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty { padding: 14px 12px; color: #888; font-size: 13px; }

  main { flex: 1; min-width: 0; overflow-y: auto; }
  .bar { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; padding: 8px 14px; background: #fff; border-bottom: 1px solid #ddd; position: sticky; top: 0; z-index: 5; }
  .bar button, .bar select { font: inherit; font-size: 14px; padding: 5px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }
  .bar button:hover { background: #eee; }
  .bar .primary, .act.primary { background: #2f6fed; color: #fff; border-color: #2f6fed; }
  .bar .primary:hover { background: #1f5fdd; }
  .bar .danger { color: #b3261e; border-color: #e0a8a4; }
  .bar .danger:hover { background: #fdeceb; }
  .bar button:disabled { opacity: .45; cursor: default; }
  .bar button.on { background: #e3ecff; border-color: #2f6fed; color: #1a5fd1; font-weight: bold; }
  .bar .sep { width: 1px; height: 22px; background: #ccc; margin: 0 4px; }
  .bar .grow { flex: 1; }
  .bar .doctitle { font-size: 14px; color: #333; }
  .crumbs { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 6px; padding: 5px 14px; background: #f7f8fa; border-bottom: 1px solid #ddd; font-size: 13px; color: #555; }
  .crumbs button { font: inherit; border: 0; background: transparent; color: #1a5fd1; cursor: pointer; padding: 0; text-decoration: underline; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .crumbs .cur { color: #222; font-weight: bold; }

  /* ボード */
  #board { display: grid; grid-template-columns: repeat(4, minmax(220px, 1fr)); gap: 12px; padding: 14px; align-items: start; overflow-x: auto; }
  .col { background: #e9ebef; border-radius: 6px; padding: 8px; min-height: 120px; }
  .col h3 { margin: 4px 6px 8px; font-size: 12px; color: #5e6c84; text-transform: uppercase; }
  .col .cnt { background: #d6d9df; border-radius: 10px; padding: 0 7px; margin-left: 4px; }
  .col.over { background: #d9e6ff; }
  .cards { min-height: 60px; }
  .card { background: #fff; border-radius: 4px; box-shadow: 0 1px 1px rgba(9,30,66,.25); padding: 8px 10px; margin-bottom: 8px; cursor: pointer; }
  .card.drag { opacity: .4; }
  .card .ct { display: block; margin-bottom: 6px; font-size: 14px; word-break: break-word; }
  .meta { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #5e6c84; }
  .meta .grow { flex: 1; }
  .tp { display: inline-block; width: 14px; height: 14px; border-radius: 3px; flex: none; }
  .av { display: inline-flex; width: 22px; height: 22px; border-radius: 50%; background: #2f6fed; color: #fff; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; }
  .av.none { background: #c1c7d0; }
  code { background: #f1f3f6; padding: 0 4px; border-radius: 3px; font-size: 12px; }

  /* 一覧 */
  #listview { padding: 14px; overflow-x: auto; }
  #listview table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #ddd; border-radius: 6px; }
  #listview th, #listview td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 14px; vertical-align: middle; }
  #listview th { font-size: 12px; color: #6b778c; background: #f7f8fa; }
  #listview tbody tr { cursor: pointer; }
  #listview tbody tr:hover { background: #f3f6fd; }
  .lz { display: inline-block; border-radius: 3px; padding: 0 6px; font-size: 11px; font-weight: bold; background: #dfe1e6; color: #42526e; }
  .lz.doing { background: #deebff; color: #0747a6; } .lz.review { background: #eae6ff; color: #403294; } .lz.done { background: #e3fcef; color: #006644; }
  .none-msg { padding: 24px 14px; color: #888; }

  /* 詳細 */
  .issue-wrap { display: grid; grid-template-columns: minmax(0, 1fr) 290px; gap: 16px; max-width: 1100px; margin: 18px auto; padding: 0 14px; align-items: start; }
  .paper { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 22px 28px; min-height: 60vh; }
  .paper h1 { margin: 0 0 14px; font-size: 1.6em; line-height: 1.3; word-break: break-word; }
  .paper h3 { margin: 22px 0 8px; font-size: 14px; color: #5e6c84; }
  .paper input[type=text], .paper textarea, .fields input, .fields select, #cBody, .dlg input { width: 100%; font: inherit; font-size: 14px; padding: 7px 9px; border: 1px solid #bbb; border-radius: 4px; background: #fff; }
  #eTitle { font-size: 1.3em; font-weight: bold; margin-bottom: 12px; }
  #eDesc { min-height: 260px; line-height: 1.7; resize: vertical; }
  #cBody { min-height: 70px; resize: vertical; }
  .desc { white-space: pre-wrap; word-break: break-word; line-height: 1.8; min-height: 40px; }
  .desc a, .cmb a, .xref { color: #1a5fd1; text-decoration: underline; cursor: pointer; }
  .placeholder { color: #999; }
  .fields { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 14px 16px; }
  .fields label { display: block; font-size: 12px; font-weight: bold; color: #6b778c; margin: 10px 0 3px; }
  .fields label:first-child { margin-top: 0; }
  .fields .info { margin-top: 14px; font-size: 12px; color: #888; line-height: 1.7; }
  .cm { border-top: 1px solid #eee; padding: 10px 0; }
  .cmh { font-size: 12px; color: #888; } .cmh b { color: #333; }
  .cmb { white-space: pre-wrap; word-break: break-word; line-height: 1.7; margin-top: 3px; }
  .kidlist { list-style: none; margin: 0; padding: 0; }
  .kidlist button { font: inherit; border: 0; background: transparent; cursor: pointer; padding: 3px 0; text-align: left; color: #1a5fd1; }
  .badge { display: inline-block; font-size: 11px; padding: 1px 8px; border-radius: 10px; margin-left: 6px; background: #e3ecff; color: #1a5fd1; vertical-align: 1px; }
  body.mode-edit .badge { background: #fff1d6; color: #9a5b00; }
  body.mode-view .edit-only { display: none !important; }
  body.mode-edit .view-only { display: none !important; }
  body.mode-edit .paper { border-color: #f0c36d; }

  /* ダイアログ */
  .dlg { position: fixed; inset: 0; z-index: 40; background: rgba(0,0,0,.35); display: flex; align-items: center; justify-content: center; padding: 16px; }
  .dlg-box { background: #fff; width: 520px; max-width: 100%; max-height: 82vh; border-radius: 8px; display: flex; flex-direction: column; padding: 16px; gap: 10px; }
  .dlg-box .t { font-weight: bold; }
  .dlg-box label { font-size: 12px; font-weight: bold; color: #6b778c; }
  .dlg-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .act { font: inherit; font-size: 14px; padding: 5px 12px; border: 1px solid #bbb; border-radius: 4px; background: #fafafa; cursor: pointer; }
  #histlist { overflow-y: auto; border: 1px solid #eee; border-radius: 4px; min-height: 80px; }
  .he { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
  .he .w { color: #888; font-size: 12px; } .he .c { margin-top: 2px; }

  @media (max-width: 720px) {
    #sidebar { position: absolute; z-index: 20; top: 0; bottom: 0; left: 0; box-shadow: 2px 0 10px rgba(0,0,0,.2); }
    .issue-wrap { grid-template-columns: 1fr; }
    .paper { padding: 16px; }
    #board { grid-template-columns: repeat(4, 78vw); }
  }
</style>
</head>
<body class="mode-view">
<header>
  <span><button id="menu" class="menu" title="チケット一覧の表示／非表示">☰</button>Ticket</span>
  <span id="status"></span>
  <span class="user">{{EMAIL}} ・ <a href="{{SCRIPT_HTML}}?action=logout">ログアウト</a></span>
</header>

<div class="layout">
  <aside id="sidebar">
    <div class="side-head">
      <div class="row">
        <select id="projSel" aria-label="プロジェクト"></select>
        <button id="projNew" title="プロジェクトを作成">＋</button>
        <button id="projEdit" title="このプロジェクトを編集">✎</button>
      </div>
      <input id="filter" type="search" placeholder="ID・タイトル・ラベルで絞り込み">
    </div>
    <ul id="doclist"></ul>
  </aside>

  <main id="main">
    <section id="home">
      <div class="bar">
        <button id="vBoard">ボード</button>
        <button id="vList">一覧</button>
        <span class="sep"></span>
        <select id="fAssignee" aria-label="担当者"></select>
        <select id="fType" aria-label="種別"></select>
        <select id="fPrio" aria-label="優先度"></select>
        <span class="grow"></span>
        <button id="newIssue" class="primary" disabled>＋ チケットを作成</button>
      </div>
      <div id="board"></div>
      <div id="listview" hidden></div>
    </section>

    <section id="detail" hidden>
      <div class="bar">
        <button id="backBtn">← 一覧へ</button>
        <span class="doctitle"><strong id="dId"></strong><span id="modebadge" class="badge"></span></span>
        <button id="editBtn" class="primary view-only">編集</button>
        <button id="saveBtn" class="primary edit-only">保存 (Ctrl+S)</button>
        <button id="saveView" class="edit-only">保存して閲覧</button>
        <button id="cancelEdit" class="edit-only">破棄して閲覧</button>
        <span class="sep"></span>
        <button id="childBtn" class="view-only" title="このチケットの下に子チケットを作る">子チケットを作成</button>
        <button id="histBtn">履歴</button>
        <button id="copyLink">🔗 リンクをコピー</button>
        <button id="delBtn" class="danger view-only">削除</button>
      </div>
      <div id="crumbs" class="crumbs" hidden></div>
      <div class="issue-wrap">
        <article class="paper">
          <h1 id="vTitle" class="view-only"></h1>
          <input id="eTitle" class="edit-only" type="text" maxlength="200" placeholder="タイトル">
          <div id="vDesc" class="desc view-only"></div>
          <textarea id="eDesc" class="edit-only" placeholder="説明（URLは自動でリンクになります。KEY-12 のようなIDは、そのチケットへのリンクになります）"></textarea>
          <div id="kidsBox" hidden><h3>子チケット</h3><ul id="kidList" class="kidlist"></ul></div>
          <div id="cmBox">
            <h3>コメント</h3>
            <div id="comments"></div>
            <textarea id="cBody" placeholder="コメントを書く"></textarea>
            <p><button id="cSend" class="act primary">コメントする</button></p>
          </div>
        </article>
        <aside class="fields">
          <label for="fStatusSel">ステータス</label><select id="fStatusSel"></select>
          <label for="fTypeSel">種別</label><select id="fTypeSel"></select>
          <label for="fPrioSel">優先度</label><select id="fPrioSel"></select>
          <label for="fAssSel">担当者</label><select id="fAssSel"></select>
          <label for="fLabels">ラベル（カンマ区切り）</label><input id="fLabels" type="text">
          <label for="fParentSel">親チケット</label><select id="fParentSel"></select>
          <div id="info" class="info"></div>
        </aside>
      </div>
    </section>
  </main>
</div>

<div id="projdlg" class="dlg" hidden>
  <div class="dlg-box" role="dialog" aria-label="プロジェクト">
    <div class="t" id="projTitle">プロジェクトを作成</div>
    <label for="pKey">キー（英大文字で始まる2〜10文字。チケット番号の接頭辞になります）</label>
    <input id="pKey" type="text" maxlength="10" placeholder="WEB">
    <label for="pName">名前</label><input id="pName" type="text" maxlength="100">
    <label for="pDesc">説明</label><input id="pDesc" type="text" maxlength="300">
    <div class="dlg-actions"><button class="act" id="pCancel">キャンセル</button><button class="act primary" id="pSave">保存</button></div>
  </div>
</div>

<div id="histdlg" class="dlg" hidden>
  <div class="dlg-box" role="dialog" aria-label="更新履歴" style="width:640px">
    <div class="t" id="histTitle">更新履歴</div>
    <div id="histlist"></div>
    <div class="dlg-actions"><button class="act" id="histClose">閉じる</button></div>
  </div>
</div>

<script>
(() => {
  const $ = id => document.getElementById(id);
  const ep = {{SCRIPT_JS}};          // index.cgi のパス（API の送信先）
  const PERMA_BASE = {{PERMA_JS}};   // パーマリンクの土台URL（空なら ?id= 形式）
  const INITIAL_ID = {{ID_JS}};      // URL で指定されたチケットID
  const ME = {{EMAIL_JS}};
  const META = {{META_JS}};          // { statuses: [[key,label]], types: [[key,label,color]], priorities: [[key,label,color,mark]] }
  const NAME_RE = /^[A-Za-z0-9_-]{1,50}$/;
  const ID_RE = /^[A-Z][A-Z0-9]{1,9}-[0-9]+$/;
  const statusEl = $('status');
  const filterEl = $('filter');
  const listEl = $('doclist');

  let state = { projects: [], users: [], issues: [] };
  let byId = new Map();     // id -> チケット（一覧用の要約）
  let kids = new Map();     // 親ID（最上位は ''）-> 子の配列
  let project = '';         // 選択中のプロジェクトキー（空ならすべて）
  let view = 'board';       // 'board' | 'list'
  let cur = null;           // 開いているチケット（新規なら id が空の下書き）
  let mode = 'view';        // 'view' | 'edit'
  let dirty = false;
  let saving = false;
  let projMode = 'new';
  try { project = localStorage.getItem('ticket_project') || ''; view = localStorage.getItem('ticket_view') || 'board'; } catch (_) {}
  const COLLAPSE_KEY = 'ticket_collapsed';
  let collapsed = new Set();
  try { collapsed = new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY) || '[]')); } catch (_) {}
  const store = (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} };

  const msg = (text, err = false) => { statusEl.textContent = text; statusEl.className = err ? 'err' : ''; };

  const el = (tag, props = {}, ...kids_) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids_.flat()) if (c != null) e.append(c);
    return e;
  };
  const entry = (list, k) => list.find(x => x[0] === k) || list[0];
  const label = (list, k) => { const e = list.find(x => x[0] === k); return e ? e[1] : k; };
  const shortName = e => (e ? e.split('@')[0] : '未割当');
  const avatar = e => el('span', { class: 'av' + (e ? '' : ' none'), title: shortName(e), text: e ? shortName(e)[0].toUpperCase() : '?' });
  const typeDot = t => el('span', { class: 'tp', style: 'background:' + entry(META.types, t)[2], title: label(META.types, t) });
  const prioMark = p => { const e = entry(META.priorities, p); return el('span', { style: 'color:' + e[2] + ';font-size:12px', title: '優先度: ' + e[1], text: e[3] }); };

  // ---------- 通信 ----------

  // サーバーがJSON以外（エラーページ等）を返した場合に、原因が分かる内容を表示する
  async function readJson(r) {
    const text = await r.text();
    try { return JSON.parse(text); } catch (_) {
      const snippet = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
      throw new Error(`サーバーの応答が不正です（HTTP ${r.status}）${snippet ? '：' + snippet : '（本文なし）'}`);
    }
  }
  // UTF-8 の文字列を base64 に変換
  function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }
  async function api(action, params = {}, post = false) {
    const url = ep + '?action=' + action + (post ? '' : '&' + new URLSearchParams(params));
    const r = await fetch(url, post ? { method: 'POST', body: new URLSearchParams(params) } : {});
    if (r.status === 401) { location.reload(); throw new Error('ログインが必要です'); }
    const j = await readJson(r);
    if (!r.ok || j.ok === false) throw new Error(j.error || r.status);
    return j;
  }

  // ---------- 一覧データ ----------

  const byNumDesc = (a, b) => (a.project === b.project ? b.num - a.num : a.project.localeCompare(b.project));

  function indexIssues() {
    byId = new Map(state.issues.map(i => [i.id, i]));
    for (const i of state.issues) {
      const p = byId.get(i.parent);
      if (!(p && p.id !== i.id && p.project === i.project)) i.parent = '';
    }
    // 親をたどっても最上位に着かない（循環）場合は、一覧から消えないよう最上位に戻す
    for (const i of state.issues) {
      let c = i.parent, n = 0;
      while (c && n++ <= state.issues.length) c = byId.get(c).parent;
      if (c) i.parent = '';
    }
    kids = new Map();
    for (const i of state.issues) {
      if (!kids.has(i.parent)) kids.set(i.parent, []);
      kids.get(i.parent).push(i);
    }
    for (const arr of kids.values()) arr.sort(byNumDesc);
  }

  function descendantIds(id) {
    const set = new Set(), stack = [id];
    while (stack.length) for (const k of kids.get(stack.pop()) || []) if (!set.has(k.id)) { set.add(k.id); stack.push(k.id); }
    return set;
  }

  async function refresh() {
    state = await api('list');
    indexIssues();
    if (project && !state.projects.some(p => p.key === project)) project = '';
    renderProjects();
    renderFilters();
    renderList();
    renderHome();
  }

  const inProject = i => !project || i.project === project;
  const textMatch = i => {
    const q = filterEl.value.trim().toLowerCase();
    return !q || (i.id + ' ' + i.title + ' ' + (i.labels || []).join(' ')).toLowerCase().includes(q);
  };
  const fieldMatch = i => {
    const a = $('fAssignee').value, t = $('fType').value, p = $('fPrio').value;
    return (!a || (a === '__me' ? i.assignee === ME : a === '__none' ? !i.assignee : i.assignee === a))
      && (!t || i.type === t) && (!p || i.priority === p);
  };

  // ---------- 画面の部品（サイドバー・フィルタ） ----------

  function renderProjects() {
    const sel = $('projSel');
    sel.replaceChildren(el('option', { value: '', text: 'すべてのプロジェクト' }),
      ...state.projects.map(p => el('option', { value: p.key, text: `${p.key}　${p.name}（未完了 ${p.open}）` })));
    sel.value = project;
    $('projEdit').disabled = !project;
  }

  function renderFilters() {
    const keep = [$('fAssignee').value, $('fType').value, $('fPrio').value];
    const opt = (v, t) => el('option', { value: v, text: t });
    $('fAssignee').replaceChildren(opt('', '担当：全員'), opt('__me', '自分'), opt('__none', '未割当'),
      ...state.users.map(u => opt(u, shortName(u))));
    $('fType').replaceChildren(opt('', '種別：すべて'), ...META.types.map(t => opt(t[0], t[1])));
    $('fPrio').replaceChildren(opt('', '優先度：すべて'), ...META.priorities.map(p => opt(p[0], p[1])));
    $('fAssignee').value = keep[0]; $('fType').value = keep[1]; $('fPrio').value = keep[2];
  }

  function makeRow(i, depth, flat) {
    const li = el('li');
    const n = (kids.get(i.id) || []).length;
    if (!flat) {
      li.style.paddingLeft = (depth * 14) + 'px';
      if (n) {
        const closed = collapsed.has(i.id);
        li.append(el('button', { class: 'tog', 'data-toggle': i.id, title: closed ? '子チケットを表示' : '子チケットを隠す', text: closed ? '▶' : '▼' }));
      } else li.append(el('span', { class: 'tog-space' }));
    }
    const b = el('button', { class: 'doc' + (cur && cur.id === i.id ? ' active' : ''), 'data-id': i.id },
      el('span', { class: 't', text: i.title }),
      el('span', { class: 'd', text: `${i.id} ・ ${label(META.statuses, i.status)} ・ ${shortName(i.assignee)}` + (n ? ` ・ 子 ${n}件` : '') }));
    li.append(b);
    return li;
  }

  function renderList() {
    listEl.replaceChildren();
    const q = filterEl.value.trim();
    const empty = t => listEl.append(el('li', { class: 'empty', text: t }));
    if (q) {
      const items = state.issues.filter(i => inProject(i) && textMatch(i)).sort(byNumDesc);
      if (!items.length) return empty('該当するチケットがありません');
      for (const i of items) listEl.append(makeRow(i, 0, true));
      return;
    }
    if (!state.issues.some(inProject)) return empty('チケットはまだありません');
    const walk = (list, depth) => {
      for (const i of list) {
        listEl.append(makeRow(i, depth, false));
        if ((kids.get(i.id) || []).length && !collapsed.has(i.id)) walk(kids.get(i.id), depth + 1);
      }
    };
    walk((kids.get('') || []).filter(inProject), 0);
  }

  // ---------- ボード・一覧 ----------

  function homeItems() { return state.issues.filter(i => inProject(i) && textMatch(i) && fieldMatch(i)); }

  function renderHome() {
    $('vBoard').classList.toggle('on', view === 'board');
    $('vList').classList.toggle('on', view === 'list');
    $('board').hidden = view !== 'board';
    $('listview').hidden = view !== 'list';
    $('newIssue').disabled = !state.projects.length;
    if (!state.projects.length) {
      $('board').hidden = true; $('listview').hidden = false;
      $('listview').replaceChildren(el('div', { class: 'none-msg', text: 'まず、左上の「＋」でプロジェクトを作成してください。' }));
      return;
    }
    const items = homeItems();
    if (view === 'board') renderBoard(items); else renderTable(items);
  }

  function renderBoard(items) {
    const board = $('board');
    board.replaceChildren();
    for (const [sk, sl] of META.statuses) {
      const mine = items.filter(i => i.status === sk).sort(byNumDesc);
      const cards = el('div', { class: 'cards' });
      for (const i of mine) {
        const n = (kids.get(i.id) || []).length;
        const card = el('div', { class: 'card', draggable: 'true', 'data-id': i.id },
          el('span', { class: 'ct', text: i.title }),
          el('div', { class: 'meta' }, typeDot(i.type), el('code', { text: i.id }), prioMark(i.priority),
            n ? el('span', { text: `子${n}` }) : null, el('span', { class: 'grow' }), avatar(i.assignee)));
        card.addEventListener('click', () => openIssue(i.id));
        card.addEventListener('dragstart', e => { e.dataTransfer.setData('text/plain', i.id); card.classList.add('drag'); });
        card.addEventListener('dragend', () => card.classList.remove('drag'));
        cards.append(card);
      }
      const col = el('section', { class: 'col', 'data-status': sk },
        el('h3', {}, sl, el('span', { class: 'cnt', text: String(mine.length) })), cards);
      col.addEventListener('dragover', e => { e.preventDefault(); col.classList.add('over'); });
      col.addEventListener('dragleave', () => col.classList.remove('over'));
      col.addEventListener('drop', e => { e.preventDefault(); col.classList.remove('over'); moveStatus(e.dataTransfer.getData('text/plain'), sk); });
      board.append(col);
    }
  }

  function renderTable(items) {
    const lv = $('listview');
    if (!items.length) return lv.replaceChildren(el('div', { class: 'none-msg', text: '該当するチケットがありません' }));
    const rows = items.slice().sort((a, b) => b.updated.localeCompare(a.updated)).map(i => {
      const tr = el('tr', {},
        el('td', {}, el('code', { text: i.id })), el('td', {}, typeDot(i.type)), el('td', { text: i.title }),
        el('td', {}, el('span', { class: 'lz ' + i.status, text: label(META.statuses, i.status) })),
        el('td', {}, prioMark(i.priority)), el('td', { text: shortName(i.assignee) }), el('td', { text: i.updated }));
      tr.addEventListener('click', () => openIssue(i.id));
      return tr;
    });
    lv.replaceChildren(el('table', {},
      el('thead', {}, el('tr', {}, ...['キー', '', 'タイトル', 'ステータス', '優先', '担当', '更新'].map(h => el('th', { text: h })))),
      el('tbody', {}, rows)));
  }

  async function moveStatus(id, st) {
    const i = byId.get(id);
    if (!i || i.status === st) return;
    const old = i.status;
    i.status = st;
    renderHome(); renderList();
    try {
      await api('save', { id, status: st }, true);
      msg(`${id} を「${label(META.statuses, st)}」にしました`);
      await refresh();
    } catch (e) {
      i.status = old; renderHome(); renderList();
      msg('ステータスの変更に失敗しました：' + e.message, true);
    }
  }

  // ---------- URL ----------

  function idFromLocation() {
    const q = new URLSearchParams(location.search).get('id');
    if (q && NAME_RE.test(q)) return q;
    const m = location.pathname.match(/\/([A-Z][A-Z0-9]{1,9}-[0-9]+)$/);
    return m ? m[1] : '';
  }
  function syncUrl(id, how = 'push') {
    if (how === 'none') return;
    const u = id ? ep + '?id=' + encodeURIComponent(id) : ep;
    if (location.pathname + location.search === u) return;
    history[how === 'replace' ? 'replaceState' : 'pushState'](null, '', u);
  }

  // ---------- 詳細 ----------

  const confirmDiscard = () => !dirty || confirm('未保存の変更があります。破棄しますか？');

  function setMode(m) {
    mode = m;
    document.body.classList.toggle('mode-edit', m === 'edit');
    document.body.classList.toggle('mode-view', m !== 'edit');
    $('modebadge').textContent = m === 'edit' ? '編集中' : '閲覧中';
  }

  function showHome(urlHow = 'push') {
    cur = null; dirty = false;
    $('detail').hidden = true; $('home').hidden = false;
    setMode('view');
    syncUrl('', urlHow);
    renderList();
  }

  // 本文中のURLと、既存チケットのID（KEY-12）をリンクにする
  function linkify(target, text) {
    target.replaceChildren();
    const re = /(https?:\/\/[^\s<>"']+)|\b([A-Z][A-Z0-9]{1,9}-[0-9]+)\b/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
      if (m.index > last) target.append(text.slice(last, m.index));
      if (m[1]) target.append(el('a', { href: m[1], target: '_blank', rel: 'noopener noreferrer', text: m[1] }));
      else if (byId.has(m[2])) {
        const id = m[2];
        target.append(el('a', { class: 'xref', title: byId.get(id).title, text: id, onclick: () => tryOpen(id) }));
      } else target.append(m[2]);
      last = m.index + m[0].length;
    }
    if (last < text.length) target.append(text.slice(last));
  }

  async function tryOpen(id) { if (confirmDiscard()) openIssue(id, { force: true }); }

  function fillSelect(sel, items, value) {
    sel.replaceChildren(...items.map(([v, t]) => el('option', { value: v, text: t })));
    sel.value = value;
  }

  function renderDetail(keepEdit = false) {
    const c = cur, isNew = !c.id;
    $('home').hidden = true; $('detail').hidden = false;
    $('dId').textContent = isNew ? `新規チケット（${c.project}）` : c.id;
    $('vTitle').textContent = c.title || '（タイトル未設定）';
    if (c.description) linkify($('vDesc'), c.description); else $('vDesc').replaceChildren(el('span', { class: 'placeholder', text: '説明はありません' }));
    if (!keepEdit) { $('eTitle').value = c.title; $('eDesc').value = c.description || ''; }

    fillSelect($('fStatusSel'), META.statuses.map(s => [s[0], s[1]]), c.status);
    fillSelect($('fTypeSel'), META.types.map(s => [s[0], s[1]]), c.type);
    fillSelect($('fPrioSel'), META.priorities.map(s => [s[0], s[1]]), c.priority);
    fillSelect($('fAssSel'), [['', '未割当'], ...state.users.map(u => [u, u])], c.assignee || '');
    $('fLabels').value = (c.labels || []).join(', ');
    const banned = c.id ? descendantIds(c.id) : new Set();
    if (c.id) banned.add(c.id);
    fillSelect($('fParentSel'), [['', '（なし）'], ...state.issues
      .filter(i => i.project === c.project && !banned.has(i.id)).sort(byNumDesc)
      .map(i => [i.id, `${i.id}　${i.title}`.slice(0, 60)])], c.parent || '');

    $('info').textContent = isNew ? '保存すると、チケット番号が付きます。' :
      `報告者：${shortName(c.reporter)}\n作成：${c.created}\n更新：${c.updated}`;
    $('info').style.whiteSpace = 'pre-line';

    // 親の階層
    const crumbs = $('crumbs');
    crumbs.replaceChildren();
    const pj = state.projects.find(p => p.key === c.project);
    crumbs.append(el('button', { text: pj ? `${pj.key} ${pj.name}` : c.project, onclick: () => { if (confirmDiscard()) { project = c.project; store('ticket_project', project); renderProjects(); showHome(); renderHome(); } } }));
    const chain = [];
    let p = c.parent;
    while (p && byId.has(p) && chain.length < 50) { chain.unshift(byId.get(p)); p = byId.get(p).parent; }
    for (const a of chain) { crumbs.append('›', el('button', { text: a.title, onclick: () => tryOpen(a.id) })); }
    if (!isNew) crumbs.append('›', el('span', { class: 'cur', text: c.id }));
    crumbs.hidden = false;

    // 子チケット
    const ks = isNew ? [] : (kids.get(c.id) || []);
    $('kidsBox').hidden = !ks.length;
    $('kidList').replaceChildren(...ks.map(k => el('li', {}, el('button', { onclick: () => tryOpen(k.id), text: `${k.id}　${k.title}（${label(META.statuses, k.status)}）` }))));

    // コメント
    $('cmBox').hidden = isNew;
    const cms = c.comments || [];
    $('comments').replaceChildren(...cms.map(m => {
      const body = el('div', { class: 'cmb' });
      linkify(body, m.body);
      return el('div', { class: 'cm' }, el('div', { class: 'cmh' }, el('b', { text: shortName(m.by) }), '　' + m.at), body);
    }));

    $('childBtn').disabled = isNew; $('histBtn').disabled = isNew; $('copyLink').disabled = isNew; $('delBtn').disabled = isNew;
    renderList();
  }

  async function openIssue(id, opts = {}) {
    if (!opts.force && !confirmDiscard()) return false;
    try {
      const j = await api('load', { id });
      cur = j.issue; dirty = false;
      setMode('view');
      renderDetail();
      syncUrl(id, opts.url || 'push');
      window.scrollTo(0, 0); $('main').scrollTop = 0;
      if (window.innerWidth <= 720) document.body.classList.add('side-closed');
      return true;
    } catch (e) {
      msg('チケットを開けませんでした：' + e.message, true);
      return false;
    }
  }

  function startNew(parent = '') {
    if (!confirmDiscard()) return;
    const pj = project || (state.projects[0] || {}).key;
    if (!pj) return msg('先にプロジェクトを作成してください', true);
    const par = parent && byId.get(parent);
    cur = { id: '', project: par ? par.project : pj, title: '', description: '', type: 'task', status: 'todo',
            priority: 'medium', assignee: ME, parent: par ? par.id : '', labels: [], comments: [] };
    dirty = false;
    setMode('edit');
    renderDetail();
    syncUrl('');
    $('eTitle').focus();
  }

  async function saveIssue(toView) {
    if (!cur || saving) return;
    const title = $('eTitle').value.trim();
    if (!title) return msg('タイトルを入力してください', true);
    const params = { id: cur.id, title, desc64: toBase64($('eDesc').value) };
    if (!cur.id) Object.assign(params, { project: cur.project, type: cur.type, status: cur.status, priority: cur.priority,
                                        assignee: cur.assignee || '', labels: (cur.labels || []).join(','), parent: cur.parent || '' });
    saving = true; msg('保存中…');
    try {
      const j = await api('save', params, true);
      cur = j.issue; dirty = false;
      if (toView || j.created) setMode('view');
      await refresh();
      renderDetail(mode === 'edit');
      syncUrl(cur.id, 'replace');
      msg(j.created ? `${cur.id} を作成しました` : '保存しました');
    } catch (e) {
      msg('保存に失敗しました：' + e.message, true);
    } finally { saving = false; }
  }

  // 右側の項目は、保存済みのチケットでは変更と同時に反映する（新規の下書きは、最初の保存でまとめて送る）
  async function fieldChanged(name, value) {
    if (!cur) return;
    if (!cur.id) {
      cur[name] = name === 'labels' ? value.split(/[,、\s]+/).filter(Boolean) : value;
      dirty = true;
      return;
    }
    try {
      const j = await api('save', { id: cur.id, [name]: value }, true);
      cur = j.issue;
      await refresh();
      renderDetail(mode === 'edit');
      msg('更新しました');
    } catch (e) {
      msg('更新に失敗しました：' + e.message, true);
      renderDetail(mode === 'edit');
    }
  }

  async function sendComment() {
    const body = $('cBody').value.trim();
    if (!cur || !cur.id || !body) return;
    try {
      const j = await api('comment', { id: cur.id, body64: toBase64(body) }, true);
      cur = j.issue; $('cBody').value = '';
      await refresh();
      renderDetail(mode === 'edit');
      msg('コメントしました');
    } catch (e) { msg('コメントに失敗しました：' + e.message, true); }
  }

  async function deleteIssue() {
    if (!cur || !cur.id) return;
    const n = (kids.get(cur.id) || []).length;
    if (!confirm(`「${cur.title}」を削除しますか？` + (n ? `\n子チケット${n}件は、ひとつ上の階層に繰り上がります。` : '') + '\n（ファイルはゴミ箱フォルダに移されます）')) return;
    try {
      await api('delete', { id: cur.id }, true);
      msg(`${cur.id} を削除しました`);
      showHome();
      await refresh();
    } catch (e) { msg('削除に失敗しました：' + e.message, true); }
  }

  function changeText(c) {
    const names = { title: 'タイトル', description: '説明', type: '種別', status: 'ステータス', priority: '優先度', assignee: '担当者', labels: 'ラベル', parent: '親チケット' };
    const f = names[c.f] || c.f;
    if (c.f === 'description') return f + 'を更新';
    const v = x => {
      if (c.f === 'status') return label(META.statuses, x);
      if (c.f === 'type') return label(META.types, x);
      if (c.f === 'priority') return label(META.priorities, x);
      if (c.f === 'labels') return (x || []).length ? x.join(', ') : 'なし';
      return x || (c.f === 'assignee' ? '未割当' : 'なし');
    };
    return `${f}：${v(c.from)} → ${v(c.to)}`;
  }

  async function showHistory() {
    if (!cur || !cur.id) return;
    try {
      const j = await api('history', { id: cur.id });
      $('histTitle').textContent = `${cur.id} の更新履歴`;
      $('histlist').replaceChildren(...(j.history.length ? j.history.map(h =>
        el('div', { class: 'he' }, el('div', { class: 'w', text: `${h.at}　${shortName(h.by)}` }),
          el('div', { class: 'c', text: h.note || h.changes.map(changeText).join(' ／ ') }))) : [el('div', { class: 'empty', text: '履歴はありません' })]));
      $('histdlg').hidden = false;
    } catch (e) { msg('履歴を取得できませんでした：' + e.message, true); }
  }

  async function copyLink() {
    if (!cur || !cur.id) return;
    const url = PERMA_BASE ? PERMA_BASE + cur.id : location.origin + ep + '?id=' + encodeURIComponent(cur.id);
    try { await navigator.clipboard.writeText(url); msg('リンクをコピーしました'); }
    catch (_) { window.prompt('このリンクをコピーしてください', url); }
  }

  // ---------- プロジェクトの作成・編集 ----------

  function openProjDlg(m) {
    projMode = m;
    const p = state.projects.find(x => x.key === project);
    $('projTitle').textContent = m === 'new' ? 'プロジェクトを作成' : 'プロジェクトを編集';
    $('pKey').value = m === 'new' ? '' : p.key; $('pKey').disabled = m !== 'new';
    $('pName').value = m === 'new' ? '' : p.name; $('pDesc').value = m === 'new' ? '' : p.desc;
    $('projdlg').hidden = false;
    (m === 'new' ? $('pKey') : $('pName')).focus();
  }

  async function saveProject() {
    const key = $('pKey').value.trim().toUpperCase();
    try {
      await api('project_save', { key, name: $('pName').value, desc: $('pDesc').value, create: projMode === 'new' ? '1' : '0' }, true);
      $('projdlg').hidden = true;
      if (projMode === 'new') { project = key; store('ticket_project', key); }
      await refresh();
      msg('プロジェクトを保存しました');
    } catch (e) { msg(e.message, true); }
  }

  // ---------- イベント ----------

  $('menu').addEventListener('click', () => document.body.classList.toggle('side-closed'));
  filterEl.addEventListener('input', () => { renderList(); renderHome(); });
  $('projSel').addEventListener('change', e => { project = e.target.value; store('ticket_project', project); renderProjects(); renderList(); renderHome(); });
  $('projNew').addEventListener('click', () => openProjDlg('new'));
  $('projEdit').addEventListener('click', () => project && openProjDlg('edit'));
  $('pCancel').addEventListener('click', () => { $('projdlg').hidden = true; });
  $('pSave').addEventListener('click', saveProject);
  $('vBoard').addEventListener('click', () => { view = 'board'; store('ticket_view', view); renderHome(); });
  $('vList').addEventListener('click', () => { view = 'list'; store('ticket_view', view); renderHome(); });
  for (const id of ['fAssignee', 'fType', 'fPrio']) $(id).addEventListener('change', renderHome);
  $('newIssue').addEventListener('click', () => startNew(''));
  $('backBtn').addEventListener('click', () => { if (confirmDiscard()) showHome(); });
  $('editBtn').addEventListener('click', () => { setMode('edit'); $('eTitle').focus(); });
  $('saveBtn').addEventListener('click', () => saveIssue(false));
  $('saveView').addEventListener('click', () => saveIssue(true));
  $('cancelEdit').addEventListener('click', () => {
    if (!confirmDiscard()) return;
    dirty = false;
    if (!cur.id) return showHome();
    setMode('view'); renderDetail();
  });
  $('childBtn').addEventListener('click', () => cur && cur.id && startNew(cur.id));
  $('histBtn').addEventListener('click', showHistory);
  $('histClose').addEventListener('click', () => { $('histdlg').hidden = true; });
  $('copyLink').addEventListener('click', copyLink);
  $('delBtn').addEventListener('click', deleteIssue);
  $('cSend').addEventListener('click', sendComment);
  $('eTitle').addEventListener('input', () => { dirty = true; });
  $('eDesc').addEventListener('input', () => { dirty = true; });
  $('fStatusSel').addEventListener('change', e => fieldChanged('status', e.target.value));
  $('fTypeSel').addEventListener('change', e => fieldChanged('type', e.target.value));
  $('fPrioSel').addEventListener('change', e => fieldChanged('priority', e.target.value));
  $('fAssSel').addEventListener('change', e => fieldChanged('assignee', e.target.value));
  $('fParentSel').addEventListener('change', e => fieldChanged('parent', e.target.value));
  $('fLabels').addEventListener('change', e => fieldChanged('labels', e.target.value));

  // サイドバー：トグルと項目のクリック
  listEl.addEventListener('click', e => {
    const t = e.target.closest('[data-toggle]');
    if (t) {
      const id = t.dataset.toggle;
      if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
      store(COLLAPSE_KEY, JSON.stringify([...collapsed]));
      return renderList();
    }
    const b = e.target.closest('button.doc');
    if (b) openIssue(b.dataset.id);
  });

  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && cur && mode === 'edit') { e.preventDefault(); saveIssue(false); }
    if (e.key === 'Escape') { $('projdlg').hidden = true; $('histdlg').hidden = true; }
  });
  window.addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });

  // ブラウザの「戻る／進む」：URLのIDに合わせて開く
  window.addEventListener('popstate', async () => {
    const id = idFromLocation();
    let ok = true;
    if (id) ok = await openIssue(id, { url: 'none' });
    else if (cur) ok = confirmDiscard() ? (showHome('none'), true) : false;
    if (!ok) syncUrl(cur ? cur.id : '', 'push');   // 移動しなかったときは、アドレスバーを元に戻す
  });

  // 画面が狭い端末ではサイドバーを閉じた状態で始める
  if (window.innerWidth <= 720) document.body.classList.add('side-closed');
  setMode('view');
  refresh()
    .then(async () => {
      const id = INITIAL_ID || idFromLocation();
      if (!id) return;
      if (!(await openIssue(id, { url: 'replace', force: true }))) syncUrl('', 'replace');
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
  if (problem = config_problem)
    return send_html(cgi, html_message('設定が不完全です', problem), '500 Internal Server Error')
  end

  action = requested_action(cgi)
  case action
  when 'login'    then handle_login(cgi)
  when 'callback' then handle_callback(cgi)
  when 'logout'   then handle_logout(cgi)
  when 'list', 'load', 'save', 'comment', 'delete', 'history', 'project_save'
    email = current_email(cgi)
    return send_json(cgi, { ok: false, error: 'login required' }, '401 Unauthorized') unless email

    case action
    when 'list'         then handle_list(cgi, email)
    when 'load'         then handle_load(cgi)
    when 'comment'      then handle_comment(cgi, email)
    when 'delete'       then handle_delete(cgi)
    when 'history'      then handle_history(cgi)
    when 'project_save' then handle_project_save(cgi, email)
    else                     handle_save(cgi, email)
    end
  else
    email = current_email(cgi)
    rid   = requested_id(cgi)
    if email
      meta = { statuses: STATUSES, types: TYPES, priorities: PRIORITIES }
      page = PAGE.sub('{{SCRIPT_JS}}') { js_literal(script_path) }
                 .sub('{{PERMA_JS}}') { js_literal(permalink_base) }
                 .sub('{{ID_JS}}') { js_literal(rid) }
                 .sub('{{EMAIL_JS}}') { js_literal(email) }
                 .sub('{{META_JS}}') { js_json(meta) }
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
  warn "[ticket] #{e.class}: #{e.message}"
  begin
    File.open(File.join(DATA_DIR, 'error.log'), 'a') { |f| f.puts "#{Time.now} #{e.class}: #{e.message}", e.backtrace.first(6) }
  rescue StandardError
    nil
  end
  begin
    send_html(CGI.new, html_message('エラーが発生しました', '時間をおいて再度お試しください。'), '500 Internal Server Error')
  rescue StandardError
    nil
  end
end
