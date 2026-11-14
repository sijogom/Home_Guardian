# Home Guardian 서버 구성

Linux 서버의 API·식별 작업·백업·OUI 갱신을 위한 systemd 구성, nginx 설정, 설치·배포 스크립트입니다.

## 설정

`.env.example`을 참고해 자신의 배포 접속 정보를 `.env.local`에 저장합니다. SSH 사용자·호스트는 `HG_RPI_USER`, `HG_RPI_HOST`로 지정하며 실제 값은 커밋하지 않습니다.

운영 인증 값은 서버의 `/etc/home-guardian/auth.env`에 별도로 준비합니다. 배포 접속용 템플릿 전체를 서버 인증 파일에 복사하지 않습니다. 토큰 서명 값, Google OAuth 클라이언트, Firebase 서비스 계정 등 설치 스크립트가 요구하는 설정과 파일 권한을 먼저 준비해야 합니다.

## 구성 파일

- `deploy/scripts/deploy.ps1`: Windows 측 배포 진입점
- `deploy/scripts/remote-install.sh`: 서버 설치와 런타임 설정 검증
- `deploy/scripts/payload-gates.ps1`: 배포 파일 검사
- `deploy/manifests/`: 배포 포함 파일 목록
- `deploy/systemd/`: 서비스·타이머·경로 감시 설정
- `deploy/nginx/`: API 프록시 구성
- `deploy/requirements-prod.txt`: 서버 의존성

배포 전 스크립트의 매개변수와 대상 경로를 확인하고 기존 서버 데이터·인증 설정을 보존합니다. 이 저장소에는 운영 환경 파일, 서비스 계정 JSON, DB, SSH 키가 포함되지 않습니다. 제공된 스크립트를 실행하면 지정한 서버 상태가 변경되므로 별도의 운영 절차에 따라 사용합니다.
