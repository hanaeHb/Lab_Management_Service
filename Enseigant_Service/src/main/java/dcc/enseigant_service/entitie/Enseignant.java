package dcc.enseigant_service.entitie;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class Enseignant {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idEnseignant;

    private String nom;

    private String prenom;

    @Column(unique = true, nullable = false)
    private String cne;

    @Column(unique = true, nullable = false)
    private String email;

    private String motDePasse;

    private String thematiqueRecherche;
}
