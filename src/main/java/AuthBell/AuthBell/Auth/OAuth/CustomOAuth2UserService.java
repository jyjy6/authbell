package AuthBell.AuthBell.Auth.OAuth;

import AuthBell.AuthBell.Auth.CustomUserDetails;
import AuthBell.AuthBell.Member.Member;
import AuthBell.AuthBell.Member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);

        // 제공자 구분 (google, kakao)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        
        String email;
        String name;
        String uniqueId;
        
        if ("google".equals(registrationId)) {
            // 구글에서 받아온 정보 추출
            email = (String) attributes.get("email");
            name = (String) attributes.get("name");
            uniqueId = email; // 구글은 이메일을 고유 식별자로 사용
            
            System.out.println("구글에서받아온정보 : ");
            System.out.println(email);
            System.out.println(name);
        } else if ("kakao".equals(registrationId)) {
            // 카카오에서 받아온 정보 추출
            String kakaoId = String.valueOf(attributes.get("id"));
            Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
            Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");
            
            // 이메일이 없을 수 있으므로 카카오 ID를 기반으로 가짜 이메일 생성
            email = kakaoAccount.get("email") != null ? 
                    (String) kakaoAccount.get("email") : 
                    "kakao_" + kakaoId + "@kakao.local";
            name = (String) profile.get("nickname");
            uniqueId = "kakao_" + kakaoId; // 카카오는 ID를 고유 식별자로 사용
            
            System.out.println("카카오에서받아온정보 : ");
            System.out.println("카카오 ID: " + kakaoId);
            System.out.println("이메일: " + email);
            System.out.println("닉네임: " + name);
        } else {
            throw new OAuth2AuthenticationException("지원하지 않는 OAuth2 제공자입니다: " + registrationId);
        }

        // DB에 있는지 확인, 없으면 새로 생성 (uniqueId로 검색)
        Member member = memberRepository.findByUsername(uniqueId)
                .orElseGet(() -> {
                    Member newMember = Member.builder()
                            .email(email)
                            .username(uniqueId) // 고유 식별자를 username으로 사용
                            .name(name != null ? name : uniqueId)
                            .displayName(name != null ? name : uniqueId)
                            .password("oauth2user")
                            .roles(new HashSet<>(Set.of("ROLE_USER", "ROLE_OAUTH")))
                            .termsAccepted(true)
                            .privacyAccepted(true)
                            .marketingAccepted(false)
                            .build();
                    return memberRepository.save(newMember);
                });

        member.setLastLogin(LocalDateTime.now());
        member.setLoginAttempts(0);
        Set<SimpleGrantedAuthority> authorities = member.getRoleSet().stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());

        return new CustomUserDetails(member, authorities, attributes);
    }

}
