package AuthBell.AuthBell.Member;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByUsername(String username);

    Optional<Member> findByEmail(String username);

    boolean existsByUsername(String username);
    boolean existsByDisplayName(String displayName);
    boolean existsByEmail(String email);

    List<Member> findTop5ByOrderByCreatedAtDesc();
    long countByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    Page<Member> findByNameContainingIgnoreCaseOrUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(
            String name, String username, String email, Pageable pageable);
}
