package AuthBell.AuthBell.Auth.JWT;


import AuthBell.AuthBell.Member.Member;
import AuthBell.AuthBell.Member.MemberDto;
import AuthBell.AuthBell.Member.MemberRepository;
import AuthBell.AuthBell.Member.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@RestController

@RequiredArgsConstructor // Lombok을 사용하여 생성자 주입
public class JWTController {

    private static final Logger log = LoggerFactory.getLogger(JWTController.class);
    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    @Value("${app.production}")
    private String appEnv;

    boolean isProduction = "production".equalsIgnoreCase(appEnv);
    @Value("${app.cookie.domain}")
    private String cookieDomain;



    @PostMapping("/api/login/jwt")
    public ResponseEntity<Map<String, Object>> loginJWT(@RequestBody Map<String, String> data, HttpServletResponse response) {
        try {


            var authToken = new UsernamePasswordAuthenticationToken(
                    data.get("username"), data.get("password")
            );

            // AuthenticationManager를 사용하여 인증 수행
            Authentication auth = authenticationManager.authenticate(authToken);
            SecurityContextHolder.getContext().setAuthentication(auth);

            // 인증된 사용자 정보 가져오기
            var auth2 = SecurityContextHolder.getContext().getAuthentication();

            // JWT 생성
            String accessToken = jwtUtil.createAccessToken(auth2);
            String refreshToken = jwtUtil.createRefreshToken(auth2.getName());

            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                    .maxAge(Duration.ofDays(7))
                    .httpOnly(true)
                    .secure(isProduction)
                    .path("/")
                    .domain(cookieDomain)
                    .sameSite("Strict") // 가장 보안 강한 설정
                    .build();
            response.addHeader("Set-Cookie", refreshCookie.toString());


            ResponseCookie accessCookie = ResponseCookie.from("accessToken", accessToken)
                    .maxAge(Duration.ofSeconds(20))
                    .httpOnly(true)
                    .secure(isProduction)
                    .path("/")
                    .domain(cookieDomain)
                    .sameSite("Strict") // 가장 보안 강한 설정
                    .build();
            response.addHeader("Set-Cookie", accessCookie.toString());
            // 응답 바디 구성
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("accessToken", accessToken);

            MemberDto memberDto = memberService.getUserInfo(auth);
            responseBody.put("userInfo", memberDto);


            return ResponseEntity.ok(responseBody);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "로그인 실패: " + e.getMessage()));
        }
    }

    @PostMapping("/api/login/guest")
    public ResponseEntity<Map<String, Object>> guestLoginJWT(HttpServletResponse response) {
        try {
            String guestMemberCode = "GUEST" + UUID.randomUUID().toString().substring(0, 8);
            String guestPassword = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            Member guestMember = new Member();
            guestMember.addRole("ROLE_GUEST");
            guestMember.addRole("ROLE_USER");
            guestMember.setPassword(passwordEncoder.encode(guestPassword));
            guestMember.setEmail("guest@guest.guest");
            guestMember.setName(guestMemberCode);
            guestMember.setUsername(guestMemberCode);
            guestMember.setDisplayName(guestMemberCode);
            memberRepository.save(guestMember);

            var authToken = new UsernamePasswordAuthenticationToken(
                    guestMemberCode, guestPassword
            );

            // AuthenticationManager를 사용하여 인증 수행
            Authentication auth = authenticationManager.authenticate(authToken);
            SecurityContextHolder.getContext().setAuthentication(auth);

            // 인증된 사용자 정보 가져오기
            var auth2 = SecurityContextHolder.getContext().getAuthentication();

            // JWT 생성
            String accessToken = jwtUtil.createAccessToken(auth2);
            String refreshToken = jwtUtil.createRefreshToken(auth2.getName());

            ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken)
                    .maxAge(Duration.ofDays(7))
                    .httpOnly(true)
                    .secure(isProduction)
                    .path("/")
                    .domain(cookieDomain)
                    .sameSite("Strict") // 가장 보안 강한 설정
                    .build();
            response.addHeader("Set-Cookie", refreshCookie.toString());

// 🔐 Access Token 쿠키 - 1시간
            ResponseCookie accessCookie = ResponseCookie.from("accessToken", accessToken)
                    .maxAge(Duration.ofSeconds(20))
                    .httpOnly(true)
                    .secure(isProduction)
                    .path("/")
                    .domain(cookieDomain)
                    .sameSite("Strict") // 가장 보안 강한 설정
                    .build();
            response.addHeader("Set-Cookie", accessCookie.toString());
            // 응답 바디 구성
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("accessToken", accessToken);

            MemberDto memberDto = memberService.getUserInfo(auth2);
            responseBody.put("userInfo", memberDto);
            log.info("유저정보");
            log.info(String.valueOf(memberDto));
            System.out.println("유저정보");
            System.out.println(memberDto);

            return ResponseEntity.ok(responseBody);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "로그인 실패: " + e.getMessage()));
        }
    }

    @GetMapping("/api/refresh-token")
    public ResponseEntity<Map<String, String>> refresh(@CookieValue(value = "refreshToken", required = false) String refreshToken, HttpServletResponse response) {
        System.out.println("새 액세스 토큰 요청됨");

        try {
            // 리프레시 토큰이 없는 경우
            if (refreshToken == null || refreshToken.isEmpty()) {
                System.out.println("리프레시 토큰이 없음");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "리프레시 토큰이 존재하지 않습니다."));
            }
            // 리프레시 토큰 만료 확인
            if (jwtUtil.isTokenExpired(refreshToken)) {
                System.out.println("토큰 만료됨");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("message", "리프레시 토큰이 만료되었습니다."));
            }

            // 리프레시 토큰에서 사용자 정보(username 또는 userId) 추출
            String username = jwtUtil.extractUsername(refreshToken);
            System.out.println("필터:유저네임" + username);

            // 새 accessToken 생성
            String newAccessToken = jwtUtil.refreshAccessToken(username);

            // 👉 ResponseCookie 객체 생성 (Spring Web)
            ResponseCookie accessCookie = ResponseCookie.from("accessToken", newAccessToken)
                    .maxAge(Duration.ofMinutes(20)) // 20분
                    .httpOnly(true)
                    .secure(isProduction) // HTTPS 환경이면 true
                    .path("/")
                    .domain(cookieDomain) // 예: "yourdomain.com"
                    .sameSite("Strict")   // 옵션: 필요시 조정 ("Lax", "Strict", "None")
                    .build();
            // 👉 응답 헤더에 쿠키 추가
            response.addHeader("Set-Cookie", accessCookie.toString());



            return ResponseEntity.ok(Map.of("message", "새 accessToken이 발급되었습니다."));
        } catch (Exception e) {
            System.out.println("토큰 갱신 중 오류 발생: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "서버 오류로 인해 액세스 토큰을 갱신할 수 없습니다."));
        }
    }



    @PostMapping("/api/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        System.out.println("로그아웃요청됨");

        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setMaxAge(0);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");
        refreshCookie.setDomain(cookieDomain);
        response.addCookie(refreshCookie);

        // AccessToken 쿠키 제거 추가
        Cookie accessCookie = new Cookie("accessToken", null);
        accessCookie.setMaxAge(0);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(isProduction);
        accessCookie.setPath("/");
        accessCookie.setDomain(cookieDomain);
        response.addCookie(accessCookie);
        System.out.println("로그아웃요청됨2");

        return ResponseEntity.ok("로그아웃 성공");
    }

    @GetMapping("/api/members/userinfo")
    public MemberDto getUserInfo(Authentication auth) {
        log.info("유저정보요청됨{}",auth);
        return memberService.getUserInfo(auth);
    }
}