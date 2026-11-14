# Home Guardian 개발 환경

`backend`, `mobile`, `scanner`, `ml`로 구성됩니다. 저장소 루트에서 다음과 같이 Python 개발 환경을 준비합니다.

```powershell
cd Home_Guardian
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

Python 의존성은 `requirements-dev.txt`, 테스트 경로는 `pyproject.toml`에서 관리합니다. 설치 가능 Python 버전은 이 파일에 지정된 패키지 버전의 지원 범위를 따라야 합니다.

- [API 실행](backend/README.md)
- [Android 앱 설정](mobile/README.md)
- [네트워크 탐색](scanner/README.md)
- [점수 계산과 학습](ml/README.md)

테스트는 격리된 환경에서 실행합니다. 실제 서비스 환경값을 테스트 프로세스에 주입하지 않습니다.
