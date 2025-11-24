package dcc.chercheur_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResponseDtoChercheur {
    private String nom;
    private String prenom;
    private String email;
    @JsonIgnore
    private String password;
    private String domaineRecherche;
    private Long idEnseignant;
    private ResponseDtoEnseignant enseignant;
}
