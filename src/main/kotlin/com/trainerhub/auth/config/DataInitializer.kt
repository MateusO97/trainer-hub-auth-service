package com.trainerhub.auth.config

import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import com.trainerhub.auth.repository.UserRepository
import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
@Profile("!prod")
class DataInitializer {
    @Bean
    fun seedUsers(
        userRepository: UserRepository,
        passwordEncoder: PasswordEncoder,
    ): CommandLineRunner =
        CommandLineRunner {
            if (userRepository.findByEmail("integration@test.com") == null) {
                userRepository.save(
                    UserEntity(
                        email = "integration@test.com",
                        passwordHash = passwordEncoder.encode("Password123"),
                        firstName = "Integration",
                        lastName = "User",
                        role = UserRole.USER,
                    ),
                )
            }
            if (userRepository.findByEmail("admin@test.com") == null) {
                userRepository.save(
                    UserEntity(
                        email = "admin@test.com",
                        passwordHash = passwordEncoder.encode("Admin1234"),
                        firstName = "Admin",
                        lastName = "User",
                        role = UserRole.ADMIN,
                    ),
                )
            }
        }
}
