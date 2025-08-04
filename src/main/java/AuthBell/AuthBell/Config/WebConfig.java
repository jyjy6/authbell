package AuthBell.AuthBell.Config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("http://localhost", "http://localhost:*", "http://localhost:3000", "http://218.38.160.152:*", "http://127.0.0.1:*", "http://0.0.0.0:*", "http://ec2-52-79-240-134.ap-northeast-2.compute.amazonaws.com:5173", "http://ec2-52-79-240-134.ap-northeast-2.compute.amazonaws.com:80", "http://ec2-52-79-240-134.ap-northeast-2.compute.amazonaws.com") // 포트 무관 허용
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
