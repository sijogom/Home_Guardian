# Home Guardian

스마트홈 네트워크의 IoT 기기를 점검하고 보안 상태와 조치 방법을 안내하는 Android 앱·API 프로젝트입니다.

## 주요 기능

- Android 네이티브 네트워크 탐색과 기기 등록·상세 조회
- 제조사·제품 식별, CVE 참조, 규칙 기반 보안 점수와 조치 안내
- Google 로그인, 사용자별 데이터 분리, 초대 코드 기반 보호자 연결
- 보호자 조회와 Firebase Cloud Messaging 알림

스캔은 소유하거나 점검 권한이 있는 네트워크에서만 실행합니다. 탐색 결과는 네트워크와 기기의 응답 여부에 따라 달라집니다.

## 구성과 실행

| 경로 | 역할 |
|---|---|
| [Home_Guardian](Home_Guardian/README.md) | 개발 환경과 검증 명령 |
| [backend](Home_Guardian/backend/README.md) | FastAPI API, 인증, 저장소 |
| [mobile](Home_Guardian/mobile/README.md) | Expo·React Native Android 앱 |
| [scanner](Home_Guardian/scanner/README.md) | 로컬 네트워크 탐색 |
| [ml](Home_Guardian/ml/README.md) | 규칙 기반·선택적 ML 점수 계산 |
| [Home_Guardian_Server](Home_Guardian_Server/README.md) | Linux 서버 설치·배포 구성 |
| [datasets](datasets/README.md) | 학습 데이터 확보 도구 |

서버 인증 값, Google OAuth 클라이언트, Firebase 설정은 자신의 실행 환경에 맞게 준비합니다. 환경 파일과 서명 키는 저장소 밖에서 관리합니다.

각 구성요소의 설치·실행 방법은 위 README에서 확인할 수 있습니다.
