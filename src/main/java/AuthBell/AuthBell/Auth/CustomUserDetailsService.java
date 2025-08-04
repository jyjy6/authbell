package AuthBell.AuthBell.Auth;

import AuthBell.AuthBell.Member.Member;
import AuthBell.AuthBell.Member.MemberRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private MemberRepository memberRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 아이디(username) 또는 이메일로 사용자 조회
        Member member = memberRepository.findByUsername(username)
                .orElseGet(() -> memberRepository.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username)));

        // 로그인 시도 후처리 (마지막 로그인 시간 업데이트 등)
        updateLoginInfo(member);

        // CustomUserDetails 객체 생성하여 반환
        return new CustomUserDetails(member);
    }

    private void updateLoginInfo(Member member) {
        // 마지막 로그인 시간 업데이트
        member.setLastLogin(LocalDateTime.now());
        // 로그인 시도 횟수 초기화 (성공적인 로그인)
        member.setLoginAttempts(0);
        // 로그인 정지 상태 해제
        member.setLoginSuspendedTime(null);
        // 변경사항 저장
        memberRepository.save(member);
    }
}