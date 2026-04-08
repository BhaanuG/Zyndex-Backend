package com.zyndex.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class ZyndexSpringBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZyndexSpringBackendApplication.class, args);
	}

}
