package dcc.projet_service.entitie;

import dcc.projet_service.dto.ResponseDtoChercheur;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class Projet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String titre;
    private String description;
    private String status;
    private Long id_chercheur;
    private Long id_enseignant;

    @Transient
    private ResponseDtoChercheur chercheur;

}

