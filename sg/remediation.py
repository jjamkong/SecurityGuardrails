from __future__ import annotations

from .models import RemediationGuide

# 취약점 유형(remediation_key)별 조치 가이드 — 방어/수정 관점만(통제 ⑦).
_KB: dict[str, RemediationGuide] = {
    "missing_hsts": RemediationGuide(
        summary="HSTS(Strict-Transport-Security) 응답 헤더를 설정한다.",
        why="HSTS가 없으면 다운그레이드/SSL stripping 공격으로 평문 접속이 강요될 수 있다.",
        how=[
            "HTTPS 응답에 'Strict-Transport-Security: max-age=31536000; includeSubDomains' 추가",
            "사전 검증 후 preload 적용 검토",
        ],
        verification="HTTPS 응답 헤더에 Strict-Transport-Security가 존재하는지 확인.",
        references=["https://owasp.org/www-project-secure-headers/"],
    ),
    "missing_csp": RemediationGuide(
        summary="Content-Security-Policy를 정의한다.",
        why="CSP가 없으면 XSS 발생 시 피해(스크립트 실행·데이터 유출)를 제한하기 어렵다.",
        how=[
            "최소 정책부터 시작: \"default-src 'self'\"",
            "report-only 모드로 영향 검증 후 enforce 전환",
        ],
        verification="응답에 Content-Security-Policy 헤더가 있고 unsafe-inline 등을 피하는지 확인.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    ),
    "missing_xfo": RemediationGuide(
        summary="클릭재킹 방지를 위해 프레임 제어를 설정한다.",
        why="X-Frame-Options/CSP frame-ancestors가 없으면 클릭재킹에 노출된다.",
        how=[
            "'X-Frame-Options: DENY' 또는 'SAMEORIGIN' 설정",
            "CSP 'frame-ancestors' 지시자로 대체/병행",
        ],
        verification="응답에 X-Frame-Options 또는 CSP frame-ancestors가 있는지 확인.",
        references=["https://owasp.org/www-community/attacks/Clickjacking"],
    ),
    "missing_xcto": RemediationGuide(
        summary="MIME 스니핑을 차단한다.",
        why="X-Content-Type-Options가 없으면 브라우저가 콘텐츠 타입을 추측해 XSS 위험이 커진다.",
        how=["'X-Content-Type-Options: nosniff' 설정"],
        verification="응답 헤더에 nosniff가 있는지 확인.",
        references=["https://owasp.org/www-project-secure-headers/"],
    ),
    "missing_referrer_policy": RemediationGuide(
        summary="Referrer-Policy를 설정한다.",
        why="과도한 Referer 전송으로 내부 URL·토큰이 외부에 노출될 수 있다.",
        how=["'Referrer-Policy: no-referrer' 또는 'strict-origin-when-cross-origin' 설정"],
        verification="응답에 Referrer-Policy가 있는지 확인.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
    ),
    "cookie_no_secure": RemediationGuide(
        summary="쿠키에 Secure 속성을 추가한다.",
        why="Secure가 없으면 평문(HTTP)으로 쿠키가 전송돼 탈취될 수 있다.",
        how=["Set-Cookie에 'Secure' 속성 추가(HTTPS 전용 전송)"],
        verification="HTTPS 세션 쿠키에 Secure가 있는지 확인.",
        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    ),
    "cookie_no_httponly": RemediationGuide(
        summary="세션 쿠키에 HttpOnly 속성을 추가한다.",
        why="HttpOnly가 없으면 XSS로 document.cookie를 통해 쿠키가 탈취될 수 있다.",
        how=["Set-Cookie에 'HttpOnly' 속성 추가"],
        verification="세션 쿠키에 HttpOnly가 있는지 확인.",
        references=["https://owasp.org/www-community/HttpOnly"],
    ),
    "cookie_no_samesite": RemediationGuide(
        summary="쿠키에 SameSite 속성을 설정한다.",
        why="SameSite가 없으면 CSRF 위험이 증가한다.",
        how=["Set-Cookie에 'SameSite=Lax'(기본 권장) 또는 'Strict' 설정"],
        verification="쿠키에 SameSite 속성이 있는지 확인.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
    ),
    "cookie_samesite_none": RemediationGuide(
        summary="SameSite=None 쿠키는 Secure와 함께, 꼭 필요한 경우에만 사용한다.",
        why="SameSite=None은 크로스사이트 전송을 허용해 CSRF 표면을 넓힌다.",
        how=[
            "교차 사이트 전송이 불필요하면 'SameSite=Lax'(또는 Strict)로 변경",
            "꼭 필요하면 반드시 'Secure'와 함께 사용",
        ],
        verification="쿠키의 SameSite가 Lax/Strict인지, None이면 Secure가 동반되는지 확인.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
    ),
    "plaintext_http": RemediationGuide(
        summary="전 구간 HTTPS를 적용하고 HTTP는 리다이렉트한다.",
        why="평문 HTTP는 도청·변조에 노출된다(자격증명·세션 탈취).",
        how=[
            "유효한 TLS 인증서로 HTTPS 제공",
            "HTTP→HTTPS 301 리다이렉트 + HSTS 적용",
        ],
        verification="http:// 접속이 https로 강제되는지 확인.",
        references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"],
    ),
    "tls_handshake": RemediationGuide(
        summary="TLS 핸드셰이크가 가능하도록 서버 TLS 설정을 점검한다.",
        why="핸드셰이크 실패는 프로토콜/암호군 미스매치 또는 서비스 미구성을 의미할 수 있다.",
        how=["지원 프로토콜(TLS 1.2+)·암호군·인증서 체인 구성 확인"],
        verification="표준 클라이언트로 TLS 연결이 성립하는지 확인.",
        references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    ),
    "tls_invalid_cert": RemediationGuide(
        summary="신뢰 가능한 CA 인증서로 교체하고 체인/호스트명을 맞춘다.",
        why="검증 실패 인증서는 MITM 경고를 유발하고 사용자가 경고를 무시하도록 학습시킨다.",
        how=["공인 CA 인증서 발급", "중간 인증서 체인 포함", "SAN에 정확한 호스트명 포함"],
        verification="표준 클라이언트에서 인증서 검증이 통과하는지 확인.",
        references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"],
    ),
    "tls_self_signed": RemediationGuide(
        summary="자가서명 인증서를 공인 CA 인증서로 교체한다.",
        why="자가서명은 신뢰 체인이 없어 MITM과 구분되지 않는다.",
        how=["Let's Encrypt 등 공인 CA 인증서 발급·적용"],
        verification="인증서 발급자가 신뢰된 CA인지 확인.",
        references=["https://letsencrypt.org/"],
    ),
    "tls_expired": RemediationGuide(
        summary="만료된 인증서를 즉시 갱신한다.",
        why="만료 인증서는 접속 차단/경고를 유발한다.",
        how=["인증서 갱신", "자동 갱신(ACME) 구성으로 재발 방지"],
        verification="not_after가 미래 시점인지 확인.",
        references=["https://letsencrypt.org/docs/"],
    ),
    "tls_expiring": RemediationGuide(
        summary="만료 임박 인증서를 미리 갱신하고 자동 갱신을 구성한다.",
        why="갱신 누락 시 서비스 중단으로 이어진다.",
        how=["자동 갱신(ACME) 설정", "만료 모니터링/알람 구성"],
        verification="자동 갱신 파이프라인 동작 확인.",
        references=["https://letsencrypt.org/docs/"],
    ),
    "exposed_git": RemediationGuide(
        summary="웹 루트에서 .git 디렉터리 노출을 차단한다.",
        why="소스코드·이력·비밀이 유출돼 추가 공격으로 이어진다.",
        how=[
            "배포 산출물에서 .git 제거",
            "서버에서 dotfile/.git 경로 접근 차단(403/404)",
        ],
        verification="/.git/HEAD 등이 200으로 응답하지 않는지 확인.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    "exposed_env": RemediationGuide(
        summary=".env 등 비밀 파일의 웹 노출을 차단하고 노출된 비밀을 폐기·교체한다.",
        why=".env에는 DB 자격증명·API 키 등이 담겨 치명적 유출이 된다.",
        how=[
            "웹 루트 밖으로 비밀 파일 이동",
            "서버에서 접근 차단",
            "노출된 자격증명 즉시 회수·교체(rotate)",
        ],
        verification="/.env 등이 접근 불가인지 확인하고 관련 비밀을 교체.",
        references=[
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/"
        ],
    ),
    "exposed_server_status": RemediationGuide(
        summary="server-status 등 운영 엔드포인트 노출을 차단한다.",
        why="내부 요청·경로·트래픽 정보가 정찰에 활용될 수 있다.",
        how=["접근을 내부망/인증으로 제한하거나 비활성화"],
        verification="/server-status가 외부에서 접근되지 않는지 확인.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    "version_banner": RemediationGuide(
        summary="서버/프레임워크 버전 배너 노출을 최소화한다.",
        why="정확한 버전은 알려진 취약점(CVE) 표적화를 쉽게 한다.",
        how=["Server/X-Powered-By 헤더 제거 또는 일반화"],
        verification="응답 헤더에 상세 버전이 드러나지 않는지 확인.",
        references=["https://owasp.org/www-project-secure-headers/"],
    ),
}


def get(key: str | None) -> RemediationGuide | None:
    if key is None:
        return None
    return _KB.get(key)
