# Boram 포크 패치 목록

> upstream `langgenius/dify` 위에 Boram 요구로 얹은 수정. **upstream 머지마다 이 목록을 재검증한다.**
> 브랜치: `boram/s1-security-patches` · 기준 커밋: `72c20daa61` (1.16.1-75)
> 각 항목: 파일:함수 — 무엇을 왜 (근거는 S0 실측: `Desktop/S0-9-게이트전수조사-2026-08-13.md`)

## S1 — 보안 패치 (마일스톤 1)

### 인증 우회 봉인
- **CONFIG-01** `controllers/console/auth/login.py` — 신규 로컬 데코레이터 `email_code_login_enabled`(:75-96, `email_password_login_enabled` 를 모방하되 `enable_email_code_login` 플래그를 봄, 비활성 시 `abort(403)`)를 `/email-code-login`(:271)·`/email-code-login/validity`(:305)·`/reset-password`(:242)에 적용. **핵심**: `ENABLE_EMAIL_CODE_LOGIN` 플래그는 이미 존재하고 기본 False(`configs/feature/__init__.py:1514`)였는데 **아무 라우트도 강제하지 않았던 것**이 취약점이었다. S0-8 엔드투엔드 실증(코드 발급→redis 평문→validity→쿠키 200). 라이브 검증: 3경로 403(이전 200), `/login`(email-password, 기본 ON) 은 200 유지. 데코레이터를 `wraps.py` 가 아니라 컨트롤러 로컬에 둬 머지 내성 확보.
  - ⚠️ 부작용: email-code 라우트를 직접 호출하던 단위 테스트 15개가 봉인 403 에 걸린다 → `@patch(...enable_email_code_login=True)` mock 추가로 해결(`test_email_verification.py`·`test_login_logout.py`).

### 무인증 엔드포인트
- **external.py:448** `BedrockRetrievalApi.post` (`POST /test/retrieval`) — 인증 데코레이터가 전혀 없어 완전 무인증으로 `ExternalDatasetTestService.knowledge_retrieval` 호출. `@setup_required`·`@login_required`·`@account_initialization_required` 3종 추가 (S0-9 HIGH #1).

### 권한 게이트 비대칭
- **workspace/model_providers.py:153** `ModelProviderCredentialApi.get` — 형제 POST(:171)엔 `@is_admin_or_owner_required` 가 있는데 GET 엔 없었다. GET 에 추가. 반환값은 이미 마스킹이라 영향은 「관리자 전용 설정 읽기 제한」 (S0-9 #19).

### fail-open → fail-closed
- **workspace/__init__.py:37-46** `plugin_permission_required` — `TenantPluginPermission` 행이 없을 때 「전원 허용」 fail-open 이었다. 기본 정책(설치=관리자만, 디버그=금지)을 적용해 fail-closed 로. `user.is_admin_or_owner` 재사용, upstream match 문은 무변경 (S0-9 P0-1).

### 역할 신설
- **models/account.py** `TenantAccountRole` — `MAKER = "maker"` 추가. 4개 집합에만 포함: `is_valid_role`·`is_non_owner_role`·`is_editing_role`(App 저작)·`is_dataset_edit_role`(Knowledge 저작, 아키텍트가 놓치기 쉽다고 지적). `is_privileged_role`·`is_admin_role` 엔 **불포함**(멤버·모델 관리 불가). `EnumText`(문자열 저장)라 DB 마이그레이션 불필요.
- **services/account_service.py:1363** `create_tenant_member` 기본 역할 `normal`→`maker`. 자동 가입 사용자가 App·Knowledge 저작 가능하되 workspace 관리는 못 하게. 다른 caller 는 명시적 role 이라 무영향.

### dataset IDOR
`DatasetService.get_dataset(id, session)`(`dataset_service.py:549`)은 tenant 필터 없는 PK 조회 → 타 tenant IDOR. 안전 변형은 `get_dataset_for_tenant`(:554)·`check_dataset_permission`(:1372). **각 사이트를 행별로 확인해 permission 검사가 없는 곳에만 추가**했다(대부분 이미 안전). `rbac_permission_required` 는 RBAC_ENABLED 기본 false 라 no-op — 이것이 IDOR 가 진짜임을 확증.

- **datasets_document.py** — 5 사이트(586·1369·1405·1440·1545). 각각 `@with_current_user` + `current_user: Account` + `check_dataset_permission` try/except→`Forbidden`. 나머지 12사이트는 이미 안전(1509 는 명시적 `tenant_id != current_tenant_id` 검사 보유).
- **datasets_segments.py** — 2 사이트(629 batch_import.post #13, 763 child_chunks.get #14). child_chunks 는 `current_user` 부재라 sibling GET 패턴대로 `@with_current_user` 배선. 10사이트 이미 안전.
- **datasets.py** — 4 사이트: 1173 api-keys(cross-tenant WRITE #5), 1244 error-docs, 1303 auto-disable-logs, **807 use-check(#4, oracle — 오케스트레이터 직접 수정)**. try/except→`Forbidden`(403).
- **metadata.py** — 1 사이트(85 GET metadata). bare `check_dataset_permission`.
- **data_source.py** — 3 사이트(246·402·422 notion sync/pre-import). bare(→ `NoPermissionError`=400).
- **hit_testing_base.py** — 무변경(91 은 96 에서 이미 검사).
- 스타일: datasets.py 는 403(try/except), metadata·data_source 는 400(bare `NoPermissionError`). 둘 다 IDOR 를 막음. 통일 필요 시 후속.

## OWN-01 — App 소유권 격리 (완료, 커밋 1c24a5f·914979·7a3708)
소유권 축은 **`maintainer`**(양도 가능 — 멤버 제거 시 owner 로 이전, `account_service.py:1776-1783`). `created_by` 는 불변 작성자 기록. read 는 소유자 OR privileged(owner/admin), mutation 은 소유자만. 정오 결정 2026-08-14.
- **OWN-01a** `controllers/console/app/wraps.py` — 두 로더에 `App.maintainer == current_user.id` (privileged 는 read bypass). `owner_only` 파라미터 신설. 불일치는 `AppNotFoundError`(404). 라이브 검증: A(maker)→B App 404, ops(owner)→B 200, B→자기 200.
- **OWN-01b** `services/app_service.py:_build_app_list_filters` — 목록 base predicate(non-privileged 면 `maintainer==me`). RBAC 무관, fail-closed. paginate/recent/starred 단일 소스.
- **OWN-01 mutation** `controllers/console/app/` 24개 mutation 라우트에 `@get_app_model(owner_only=True)`. GET·실행·copy/export·협업코멘트는 admin readable 유지.
- 이스컬레이션(별도): `app.py:1073` publish-to-external(정오 판단), `workflow_draft_variable.py` 공유 `_api_prerequisite` 5개 mutation(read/write 분리 필요), 멤버관리(`invite-email`)는 upstream 부터 admin 게이트 부재.

## 다음 마일스톤 — AUTH-01 (설계 확정, 구현 대기)
Firebase ID token → Dify 콘솔 세션 교환. **기존 OAuth 컨트롤러(`oauth.py`)의 near-clone.**
- 엔드포인트: `POST /console/api/firebase-exchange` (신규 `controllers/console/auth/firebase_exchange.py`, `__init__.py:86-95` 등록). `@setup_required` 만.
- **`firebase-admin` 패키지 추가 필요** (`pyproject.toml` 에 없음 → 이미지 rebuild 전제).
- 검증: `verify_id_token(check_revoked=True)` + `email_verified` + **정확 도메인**(`rsplit("@",1)[1].lower()=="hanyang.ac.kr"`, endswith 금지).
- uid 매핑: 기존 `AccountIntegrate` + `link_account_integrate("firebase",...)` — **새 컬럼 불필요**.
- 프로비저닝: `create_account(is_setup=True)`(계정만, workspace 안 만듦) → `create_tenant_member(HANYANG_WORKSPACE_ID, role="maker")`(멱등) → `link_account_integrate` → `AccountService.login` → 쿠키 3종. **`create_account_and_tenant`·`_generate_account` 절대 재사용 금지**(workspace 생성 경로).
- 2번째 workspace 방지: `ALLOW_CREATE_WORKSPACE=False`(기본) + Hanyang join 선행(`:1298-1306` no-op) + `is_setup` 은 `create_account` 에만.
- cross-origin: SameSite=Lax 라 boram 은 **same-origin 프록시**(권장) 또는 1회용 code redirect. `web/` 안 건드림(LICENSE:11).
- config 추가: `FIREBASE_PROJECT_ID`·`FIREBASE_CREDENTIALS_JSON`·`HANYANG_WORKSPACE_ID`·`FIREBASE_EXCHANGE_ENABLED`.
- 스토리 5개: a(deps+config) → b(verifier libs/firebase.py) → c(provisioning) → d(endpoint) → e(boram 프록시).

## 그 다음
- D-2 통제: 공용 credential 게이트웨이 (사용량 귀속·상한), Redis 평문 캐시
- 멤버관리 admin 게이트 (invite-email 등 — OWN-01 에서 발견)
- route-table diff CI + default-deny 프록시
- `RBAC_ENABLED=false` 에서 `edit_permission_required`/`is_admin_or_owner_required` 가 배타적으로 도는 반전 (설계 결정)
