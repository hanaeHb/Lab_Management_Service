package dcc.chercheur_service.dto;



import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class RequestDtoChercheur {
    private String nom;
    private String prenom;
    private String email;
    private String password;
    private String domaineRecherche;
    private Long idEnseignant;
}
