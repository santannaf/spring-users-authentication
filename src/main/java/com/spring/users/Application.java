package com.spring.users;

import com.spring.users.auth.property.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfiguration.class)
@ComponentScan("com.spring.users.auth")
public class Application {
	public static void main(String... args) {
		SpringApplication.run(Application.class, args);
	}
}
