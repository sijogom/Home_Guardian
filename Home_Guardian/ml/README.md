# 보안 점수와 ML

`home_guardian_ml/scoring.py`가 규칙 기반 점수와 한국어 안내를 계산합니다. `hybrid_scoring.py`는 사용 가능한 학습 모델이 있을 때 공격 확률을 보수적으로 반영하며, 모델이 없으면 규칙 기반 결과를 사용합니다. 점수는 프로젝트 자체 평가 지표이며 보안 인증을 뜻하지 않습니다.

## 학습과 검증

상위 `Home_Guardian/`에서 개발 의존성과 실제 학습 데이터를 준비한 뒤 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m ml.training.train --datasets unsw-nb15 ton-iot cic-iot-2023 --max-rows 200000
.\.venv\Scripts\python.exe -m pytest ml/tests
```

`training/train_lightweight.py`는 모바일 탐색 결과에 사용하는 경량 모델 학습 경로입니다. 전체 특성 모델과 경량 모델의 입력 계약은 다르므로 서로 바꾸어 사용하지 않습니다. 원시 데이터와 학습 모델은 별도로 준비합니다.
