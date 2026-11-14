# Home Guardian Android 앱

Expo·React Native와 로컬 Android 네트워크 스캐너 모듈을 사용합니다. 네이티브 모듈이 있으므로 Expo Go만으로 전체 기능을 실행할 수 없습니다.

## 준비

- Node.js와 `package-lock.json`에 맞는 npm 설치 환경
- Android SDK·JDK와 Android 개발 빌드 환경
- 자신의 Google OAuth 클라이언트 및 Firebase 프로젝트
- `app.json`의 패키지명과 일치하는 `google-services.json` (Git 제외)

이 디렉터리에서 `.env.example`을 `.env.local`로 복사해 API 주소와 Google 클라이언트 ID를 설정합니다. `EXPO_PUBLIC_*` 값은 앱 번들에서 읽을 수 있으므로 비밀 키를 넣지 않습니다.

```powershell
npm ci
npm run typecheck
npm test -- --runInBand
npm run android:dev
```

개발용 로컬 HTTP 연결은 `HG_ALLOW_CLEARTEXT_DEV=1`을 명시한 경우에만 허용합니다. 릴리스는 HTTPS API를 사용하며 `HG_RELEASE_BUILD=1` 등 릴리스 설정이 개발 예외보다 우선합니다.

`npm run verify`는 소스 계약을 검사하며, 먼저 네이티브 Android 프로젝트가 생성되어 있어야 합니다. 저장소에는 생성된 `android/` 디렉터리가 포함되지 않으므로 Firebase 설정을 준비하고 `npm run android:dev` 등 Expo 네이티브 생성 경로를 거쳐야 합니다. Google 로그인, LAN 탐색, 푸시 알림은 Android 기기에서 필요한 권한을 허용한 뒤 사용합니다. 릴리스 서명 키와 Firebase 설정은 로컬에서 관리합니다.
