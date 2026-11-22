# インストール・設定方法

## 必要なもの

- Ruby 2.6 が利用できる環境
- CGI が利用できる Web サーバー
- HTTPS でアクセスできるドメイン
- Google Cloud プロジェクトと OAuth クライアント

## 1. ファイルの配置

`index.cgi` と `config.json` を同じディレクトリに配置します。

```text
wiki/
├── index.cgi
├── config.json
└── data/
```

`data/` ディレクトリは、アプリケーションの起動時に存在しなければ自動作成されます。

## 2. Google OAuth の設定

Google Cloud Console で OAuth クライアント ID を作成します。
OAuth クライアントの種類は「ウェブ アプリケーション」を選択してください。

承認済みのリダイレクト URI に、`config.json` の `redirect_uri` と同じ URL を登録します。

### config.json の例

```json
{
  "google_client_id": "YOUR_GOOGLE_CLIENT_ID",
  "google_client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
  "redirect_uri": "https://example.com/wiki/index.cgi?action=callback",
  "session_secret": "YOUR_RANDOM_SECRET",
  "allowed_emails": [
    "user@example.com"
  ],
  "permalink_base": "https://example.com/wiki/"
}
```

### 設定項目

| 設定項目 | 説明 |
|---|---|
| `google_client_id` | Google OAuth クライアント ID |
| `google_client_secret` | Google OAuth クライアントシークレット |
| `redirect_uri` | OAuth 認証後の戻り先 URL |
| `session_secret` | セッション署名に使用する秘密鍵 |
| `allowed_emails` | アクセスを許可するメールアドレスの配列 |
| `permalink_base` | ページリンクのベース URL |

`permalink_base` は省略できます。省略した場合は `index.cgi?id=ページID` 形式の URL を使用します。

`session_secret` には、推測されにくい十分に長いランダムな文字列を設定してください。
`google_client_secret` や `session_secret` を GitHub などの公開リポジトリに登録しないでください。

## 3. パーミッションの設定

設置環境に合わせて、ファイルとディレクトリのパーミッションを設定します。

```bash
chmod 700 index.cgi
chmod 600 config.json
chmod 705 data
```

CGI の先頭行（shebang）は、サーバー上の Ruby のパスに合わせて変更してください。

例：

```ruby
#!/usr/local/bin/ruby2.6
```

## 4. Wiki へのアクセス

ブラウザで次の URL にアクセスします。

```text
https://example.com/wiki/index.cgi
```

許可された Google アカウントでログインすると、Wiki を利用できます。
