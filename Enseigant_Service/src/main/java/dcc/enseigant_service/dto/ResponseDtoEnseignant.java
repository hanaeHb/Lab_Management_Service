package dcc.enseigant_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class ResponseDtoEnseignant {
    private Long idEnseignant;
    private String nom;
    private String prenom;
    private String cne;
    private String email;
    @JsonIgnore
    private String motDePasse;
    private String thematiqueRecherche;
}
