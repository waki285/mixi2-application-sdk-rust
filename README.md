# mixi2 Application SDK for Go

mixi2 の Application API を利用するための Go SDK です。

## インストール

```bash
go get github.com/mixigroup/mixi2-application-sdk-go
```

## 機能

| パッケージ | 機能 |
|------------|------|
| `auth` | OAuth2 Client Credentials 認証（アクセストークンの取得・キャッシュ・自動更新） |
| `event` | イベントハンドリングのインターフェース定義 |
| `event/webhook` | HTTP Webhook サーバーによるイベント受信 |
| `event/stream` | gRPC ストリーミングによるイベント受信 |

## クイックスタート

### 認証

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/mixigroup/mixi2-application-sdk-go/auth"
)

func main() {
    authenticator, err := auth.NewAuthenticator(
        os.Getenv("CLIENT_ID"),
        os.Getenv("CLIENT_SECRET"),
        os.Getenv("TOKEN_URL"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // gRPC リクエスト用のコンテキストを取得
    ctx, err := authenticator.AuthorizedContext(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    // ctx を使って gRPC リクエストを送信
    _ = ctx
}
```

### Webhook サーバー

```go
package main

import (
    "context"
    "crypto/ed25519"
    "encoding/hex"
    "log"
    "os"

    "github.com/mixigroup/mixi2-application-sdk-go/event/webhook"
    modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
)

type MyHandler struct{}

func (h *MyHandler) Handle(ctx context.Context, ev *modelv1.Event) error {
    log.Printf("Received event: %v", ev)
    return nil
}

func main() {
    publicKeyHex := os.Getenv("PUBLIC_KEY")
    publicKey, err := hex.DecodeString(publicKeyHex)
    if err != nil {
        log.Fatal(err)
    }

    server := webhook.NewServer(
        ":8080",
        ed25519.PublicKey(publicKey),
        &MyHandler{},
    )

    if err := server.Start(); err != nil {
        log.Fatal(err)
    }
}
```

### gRPC ストリーミング

```go
package main

import (
    "context"
    "log"
    "os"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    "github.com/mixigroup/mixi2-application-sdk-go/auth"
    "github.com/mixigroup/mixi2-application-sdk-go/event/stream"
    application_streamv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/service/application_stream/v1"
    modelv1 "github.com/mixigroup/mixi2-application-sdk-go/gen/go/social/mixi/application/model/v1"
)

type MyHandler struct{}

func (h *MyHandler) Handle(ctx context.Context, ev *modelv1.Event) error {
    log.Printf("Received event: %v", ev)
    return nil
}

func main() {
    authenticator, err := auth.NewAuthenticator(
        os.Getenv("CLIENT_ID"),
        os.Getenv("CLIENT_SECRET"),
        os.Getenv("TOKEN_URL"),
    )
    if err != nil {
        log.Fatal(err)
    }

    conn, err := grpc.NewClient(
        os.Getenv("API_ADDRESS"),
        grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := application_streamv1.NewApplicationServiceClient(conn)
    watcher := stream.NewStreamWatcher(client, authenticator)

    if err := watcher.Watch(context.Background(), &MyHandler{}); err != nil {
        log.Fatal(err)
    }
}
```

## 開発

### 必要なツール

- Go 1.24.6 以上
- [buf](https://buf.build/) (proto からのコード生成用)

## フィードバック・バグ報告
この SDK は mixi2 チームが管理しています。
プルリクエストは受け付けておりませんが、フィードバックは歓迎します。
詳しくは [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## セキュリティ

- セキュリティ報告: [SECURITY.md](SECURITY.md)
- `CLIENT_SECRET` は環境変数やシークレット管理システムから読み込んでください。ソースコードにハードコードしないでください。
- イベント署名は Ed25519 で検証されます。
- タイムスタンプ検証によりリプレイ攻撃を防止します（5分間のウィンドウ）。

## ライセンス

[LICENSE](LICENSE) を参照してください。
