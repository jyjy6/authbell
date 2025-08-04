package AuthBell.AuthBell;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class AuthBellApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthBellApplication.class, args);
		log.warn("안녕하세요 AuthBell 입니다!");
	}

}
