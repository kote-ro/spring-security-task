package com.example.task.configuration;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@ComponentScan("com.example.task.configuration")
@PropertySource(value = "classpath:application.properties")
public class SpringProfilesConfig {

}
