# web_ui

Svelte 5 + Vite ベースのブラウザ UI。

## セットアップ

```bash
cd web_ui
npx pnpm install
```

## 開発

```bash
npx pnpm dev
```

Vite は `/api/*` と `/openapi.json` を `http://127.0.0.1:8000` に proxy する。

## ビルド

```bash
npx pnpm build
```

成果物は `web_ui/dist/` に出力され、`forensia serve` がそのまま配信する。

## 型生成

```bash
npx pnpm gen:api
```

`/openapi.json` から `src/api/types.ts` を再生成する。
