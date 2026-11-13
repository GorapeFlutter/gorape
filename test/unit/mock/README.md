# Unit Test Mock Directory

このディレクトリには、単体テスト用のモック実装が含まれています。

## 構造

```
mock/
├── server/
│   ├── controller/  # Controllerのモック
│   ├── usecase/     # Usecaseのモック
│   ├── repository/  # Repositoryのモック
│   └── middleware/  # Middlewareのモック
└── client/
    ├── controller/  # Controllerのモック
    ├── usecase/     # Usecaseのモック
    └── repository/  # Repositoryのモック
```

## モックの生成

モックは`go.uber.org/mock/mockgen`を使用して生成します。

```bash
# Repository のモック生成例
mockgen -source=pkg/server/repository/user.go -destination=test/unit/mock/server/repository/user_mock.go -package=mock_repository

# Usecase のモック生成例
mockgen -source=pkg/server/usecase/user.go -destination=test/unit/mock/server/usecase/user_mock.go -package=mock_usecase
```

## 使用方法

```go
import (
    mock_repository "github.com/Gorapeflutter/gorape/test/unit/mock/server/repository"
    "go.uber.org/mock/gomock"
)

func TestExample(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    mockRepo := mock_repository.NewMockUserRepository(ctrl)
    mockRepo.EXPECT().GetUser(gomock.Any()).Return(expectedUser, nil)

    // Test code using mockRepo
}
```
