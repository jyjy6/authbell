package AuthBell.AuthBell.Auth.JWT;

import AuthBell.AuthBell.Auth.CustomUserDetails;
import AuthBell.AuthBell.Auth.CustomUserDetailsService;
import AuthBell.AuthBell.Auth.GlobalErrorHandler.GlobalException;
import AuthBell.AuthBell.Member.Member;
import AuthBell.AuthBell.Member.MemberDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.io.Resource;
import java.nio.charset.StandardCharsets;

@Component
public class JWTUtil {

    private final CustomUserDetailsService customUserDetailsService;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JWTUtil(CustomUserDetailsService customUserDetailsService,
                   @Value("${jwt.private-key}") Resource privateKeyResource,
                   @Value("${jwt.public-key}") Resource publicKeyResource) throws Exception {
        this.customUserDetailsService = customUserDetailsService;

        // Private Key 로드
        byte[] privateKeyBytes = privateKeyResource.getInputStream().readAllBytes();
        String privateKeyPEM = new String(privateKeyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "")
                .trim();
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Public Key 로드
        byte[] publicKeyBytes = publicKeyResource.getInputStream().readAllBytes();
        String publicKeyPEM = new String(publicKeyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "")
                .trim();
        byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
        this.publicKey = keyFactory.generatePublic(publicKeySpec);
    }

    // JWT 만들어주는 함수
    public String createAccessToken(Authentication auth) {

        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        Member member = userDetails.getMember();

        Set<String> roleSet = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // 원하는 정보만 포함한 DTO 생성
        MemberDto memberDto = MemberDto.builder()
                .id(member.getId())
                .username(member.getUsername())
                .displayName(member.getDisplayName())
                .roleSet(roleSet)
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        String memberJson = "";
        try {
            memberJson = objectMapper.writeValueAsString(memberDto);
        } catch (JsonProcessingException e) {
            throw new GlobalException("사용자 정보를 JSON으로 변환하는 중 오류가 발생했습니다", "JSON_CONVERSION_ERROR", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return Jwts.builder()
                .setSubject(member.getUsername())
                .claim("userInfo", memberJson) // JSON 형태로 저장
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 20000))
                .signWith(privateKey)
                .compact();
    }

    //    jwt재발급 해주는 메소드-> AccessToken이 만료되면 Authentication auth는 무효가 되기때문에 username으로 사용자 정보를 로드
    public String refreshAccessToken(String username) {

        CustomUserDetails userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);

        // 사용자 정보를 기반으로 Authentication 객체 생성 (패스워드는 null로 설정)
        Authentication auth = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        // 이제 기존의 createAccessToken(Authentication auth) 로직을 재사용할 수 있음
        CustomUserDetails customUserDetails = (CustomUserDetails) auth.getPrincipal();
        Member member = customUserDetails.getMember();

        Set<String> roleSet = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        MemberDto memberDto = MemberDto.builder()
                .id(member.getId())
                .username(member.getUsername())
                .displayName(member.getDisplayName())
                .roleSet(roleSet)
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        String userInfoJson = "";
        try {
            userInfoJson = objectMapper.writeValueAsString(memberDto);
        } catch (JsonProcessingException e) {
            throw new GlobalException("사용자 정보를 JSON으로 변환하는 중 오류가 발생했습니다", "JSON_CONVERSION_ERROR", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return Jwts.builder()
                .setSubject(member.getUsername())
                .claim("userInfo", userInfoJson)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 900000))
                .signWith(privateKey)
                .compact();
    }

    public String createRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 604800000)) // 7일 유효
                .signWith(privateKey)
                .compact();
    }

    //JWT 토큰에서 클레임(Claims)을 추출하는 기능을 수행
    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    //이 메서드는 JWT 토큰이 만료되었는지 여부를 확인하는 기능을 수행
    public boolean isTokenExpired(String token) {
        try {
            final Date expiration = extractClaims(token).getExpiration();
            return expiration.before(new Date());
        } catch (ExpiredJwtException e) {
            System.out.println("토큰이 만료되었습니다: " + e.getMessage());
            return true;
        } catch (Exception e) {
            System.out.println("토큰 검증 중 오류 발생: " + e.getMessage());
            return true; // 오류 났으면 만료된 걸로 간주
        }
    }

    //이 메서드는 JWT 토큰에서 사용자 이름을 추출하는 기능을 수행
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }
}