# Home Guardian API

FastAPI 기반 인증·기기 점검·보호자 연결 API입니다. SQLite 저장소와 SQLAlchemy 기반 저장소 구현을 포함합니다.

## 로컬 실행

먼저 상위 디렉터리의 Python 개발 의존성을 설치합니다. 아래 명령의 작업 위치는 `Home_Guardian/`입니다.

```powershell
$env:HG_AUTH_TOKEN_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
# GOOGLE_CLIENT_ID 등 외부 서비스 설정은 자신의 환경에서 주입합니다.
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8010
```

`/health`에서 상태를 확인합니다. Google 로그인과 푸시 알림을 사용하려면 해당 서비스 설정을 준비합니다. 운영 환경의 필수 키와 파일 경로는 [서버 설정 템플릿](../../Home_Guardian_Server/.env.example)을 참고하세요. 배포 접속용 설정과 서버 런타임 설정은 구분합니다.

## 검증

상위 디렉터리에서 `python -m pytest backend/tests`를 실행합니다. 기본 pytest 설정은 `backend`, `scanner`, `ml`을 import 경로에 추가합니다. 네트워크 스캔은 점검 권한이 있는 환경에서 실행합니다.
