package dcc.chercheur_service.entitie;

import dcc.chercheur_service.dto.ResponseDtoEnseignant;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Chercheur {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idChercheur;

    private String nom;
    private String prenom;
    @Column(unique = true, nullable = false)
    private String email;
    private String password;
    private String domaineRecherche;
    private Long idEnseignant;

    @Transient
    private ResponseDtoEnseignant enseignant;
}
