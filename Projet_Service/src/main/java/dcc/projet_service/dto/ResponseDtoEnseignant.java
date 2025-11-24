package dcc.projet_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

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
