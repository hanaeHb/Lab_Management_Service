package dcc.projet_service;

import dcc.projet_service.configuration.RsaKeys;
import dcc.projet_service.entitie.Projet;
import dcc.projet_service.repository.ProjetRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeys.class)
@EnableFeignClients
public class ProjetServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProjetServiceApplication.class, args);
	}

	/*
	@Bean
	CommandLineRunner commandLineRunner(ProjetRepository projetRepository){
		return args -> {
			projetRepository.save(Projet.builder()
					.titre("AI For Smart HealthCare")
					.description("use AI tools for Smart HealthCare monitoring ")
					.id_chercheur(1L)
					.id_enseignant(1L)
					.build());

		};
	}*/
}
