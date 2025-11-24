package dcc.enseigant_service.dto;


import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor


public class RequestDtoEnseignant {

    private String nom;
    private String prenom;
    private String cne;
    private String email;
    private String motDePasse;
    private String thematiqueRecherche;
}
