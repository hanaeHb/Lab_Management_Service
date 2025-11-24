package dcc.enseigant_service;

import dcc.enseigant_service.configuration.RsaKeys;

import dcc.enseigant_service.entitie.Enseignant;
import dcc.enseigant_service.repository.EnseignantRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeys.class)
@EnableFeignClients
public class EnseigantServiceApplication {


    public static void main(String[] args) {
        SpringApplication.run(EnseigantServiceApplication.class, args);

    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    /*
    @Bean
    CommandLineRunner commandLineRunner(EnseignantRepository enseignantRepository){
        return args -> {
            enseignantRepository.save(Enseignant.builder()
                    .nom("Walid")
                    .prenom("Hajoub")
                    .cne("LA11222")
                    .email("walid@gmail.com")
                    .motDePasse(new BCryptPasswordEncoder().encode("1234"))
                    .thematiqueRecherche("IA, Big Data")
                    .build());

        };
    }*/


}
