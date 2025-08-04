package AuthBell.AuthBell.Auth.OAuth;

import AuthBell.AuthBell.Auth.GlobalErrorHandler.GlobalException;
import AuthBell.AuthBell.Auth.JWT.JWTUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @Value("${app.production}")
    private String appEnv;

    boolean isProduction = "production".equalsIgnoreCase(appEnv);
    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        System.out.println("성공!");

        try {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            
            // 제공자에 따라 이메일 추출 방식 다름
            String email;
            Map<String, Object> attributes = oAuth2User.getAttributes();
            
            if (attributes.containsKey("email")) {
                // 구글의 경우
                email = oAuth2User.getAttribute("email");
            } else if (attributes.containsKey("kakao_account")) {
                // 카카오의 경우
                Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
                String kakaoId = String.valueOf(attributes.get("id"));
                
                // 이메일이 없으면 카카오 ID 기반으로 생성
                email = kakaoAccount.get("email") != null ? 
                        (String) kakaoAccount.get("email") : 
                        "kakao_" + kakaoId;
            } else {
                throw new GlobalException("OAuth2 사용자 정보를 찾을 수 없습니다", "OAUTH2_USER_INFO_NOT_FOUND", HttpStatus.BAD_REQUEST);
            }

            String accessToken = jwtUtil.createAccessToken(authentication);
            String refreshToken = jwtUtil.createRefreshToken(email);

            // 쿠키 설정
            Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
            refreshCookie.setMaxAge(60 * 60 * 24 * 30);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setPath("/");
            refreshCookie.setAttribute("SameSite", "lax");
            refreshCookie.setSecure(isProduction);
            if (isProduction) {
                refreshCookie.setDomain(cookieDomain);
            }
            response.addCookie(refreshCookie);

            // 프론트엔드 URL로 리다이렉트 (토큰을 쿼리 파라미터로)
            String frontendUrl = isProduction ?
                    "https://yourdomain.com/oauth/callback" :
                    "http://localhost/oauth/callback";

            String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl)
                    .queryParam("accessToken", accessToken)
                    .build().toUriString();

            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } catch (Exception e) {
            System.err.println("인증 성공 핸들러 오류: " + e.getMessage());
            e.printStackTrace();

            // 에러 시 프론트엔드 에러 페이지로 리다이렉트
            String errorUrl = isProduction ?
                    "https://yourdomain.com/oauth/error" :
                    "http://localhost:5173/oauth/error";
            getRedirectStrategy().sendRedirect(request, response, errorUrl);
        }
    }
}