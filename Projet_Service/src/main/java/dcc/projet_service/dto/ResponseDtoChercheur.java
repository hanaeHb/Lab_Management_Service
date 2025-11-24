package dcc.projet_service.dto;

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
    private String domaineRecherche;
    private Long idEnseignant;
    private ResponseDtoEnseignant enseignant;
}
