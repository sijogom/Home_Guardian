# 로컬 네트워크 탐색

Windows 로컬 탐색기는 지정한 CIDR 또는 PC의 기본 IPv4 대역에서 실제 응답하는 호스트를 확인합니다. 방화벽·공유기 설정에 따라 결과가 비어 있을 수 있습니다.

상위 `Home_Guardian/`에서 개발 의존성을 설치한 뒤 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m scanner.home_guardian_scanner.local_discovery
.\.venv\Scripts\python.exe -m pytest scanner/tests
```

소유하거나 점검 권한이 있는 네트워크에서만 사용합니다. 테스트용 연결 대체 객체는 테스트 디렉터리에만 존재하며 실제 점검 결과를 대신하지 않습니다.
