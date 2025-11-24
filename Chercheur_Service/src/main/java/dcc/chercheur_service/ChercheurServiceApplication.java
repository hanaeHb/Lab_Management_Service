package dcc.chercheur_service;

import dcc.chercheur_service.configuration.RsaKeys;
import dcc.chercheur_service.entitie.Chercheur;
import dcc.chercheur_service.repository.ChercheurRepository;
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
public class ChercheurServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChercheurServiceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    /*
    @Bean
    CommandLineRunner commandLineRunner(ChercheurRepository chercheurRepository){
        return args -> {
            chercheurRepository.save(Chercheur.builder()
                    .nom("ali")
                    .prenom("mrini")
                    .domaineRecherche("IA")
                    .email("ali@gmail.com")
                    .password(new BCryptPasswordEncoder().encode("1234"))
                    .idEnseignant(1L)
                    .build());

        };
    }
        */

}
