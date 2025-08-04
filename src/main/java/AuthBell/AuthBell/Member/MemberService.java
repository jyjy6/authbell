package AuthBell.AuthBell.Member;

import AuthBell.AuthBell.Auth.CustomUserDetails;
import AuthBell.AuthBell.Auth.GlobalErrorHandler.GlobalException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;


    public MemberDto getUserInfo(Authentication auth) {
        // 인증 확인
        if (auth == null || auth.getPrincipal() == null) {
            throw new GlobalException("로그인이 필요합니다", "LOGIN_REQUIRED", HttpStatus.UNAUTHORIZED);
        }
        String username = ((CustomUserDetails)auth.getPrincipal()).getUsername();
        // 사용자 조회
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new GlobalException("사용자를 찾을 수 없습니다", "MEMBER_NOT_FOUND", HttpStatus.NOT_FOUND));
        // DTO 변환
        MemberDto memberDto = new MemberDto();
        return memberDto.convertToDetailMemberDto(member);
    }
}
