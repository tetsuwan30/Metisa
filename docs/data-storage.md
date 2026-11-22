# データ保存形式

Wiki はデータベースを使用せず、ファイルシステムにページ情報を保存します。

## ディレクトリ構成

```text
data/
├── <page_id>.html
├── <page_id>.title
├── <page_id>.parent
├── <page_id>.status
├── images/
│   └── <image_id>.<extension>
├── history/
│   └── <page_id>/
│       ├── <revision_id>.html
│       └── <revision_id>.meta
└── trash/
```

## ファイル・ディレクトリ

| ファイル・ディレクトリ | 内容 |
|---|---|
| `<page_id>.html` | ページ本文 |
| `<page_id>.title` | ページタイトル |
| `<page_id>.parent` | 親ページ ID |
| `<page_id>.status` | ページのステータス |
| `images/` | アップロードされた画像 |
| `history/` | ページの更新履歴 |
| `trash/` | 削除したページと関連データ |

`data/` ディレクトリには、Web サーバーからの直接アクセスを拒否する `.htaccess` を自動作成します（`.htaccess` に対応する Apache 環境の場合）。
