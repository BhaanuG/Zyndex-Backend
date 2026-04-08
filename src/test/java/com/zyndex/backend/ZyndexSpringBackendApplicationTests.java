package com.zyndex.backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.TestConstructor;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestConstructor(autowireMode = TestConstructor.AutowireMode.ALL)
class ZyndexSpringBackendApplicationTests {
	private final AppProperties properties;
	private final Environment environment;

	ZyndexSpringBackendApplicationTests(AppProperties properties, Environment environment) {
		this.properties = properties;
		this.environment = environment;
	}

	@Test
	void contextLoads() {
	}

	@Test
	void loadsOtpMailConfigFromExistingEnvFile() {
		assertThat(properties.otpMailFrom()).isNotBlank();
		assertThat(environment.getProperty("spring.mail.host")).isNotBlank();
		assertThat(environment.getProperty("spring.mail.username")).isNotBlank();
		assertThat(environment.getProperty("spring.mail.password")).isNotBlank();
	}

}
