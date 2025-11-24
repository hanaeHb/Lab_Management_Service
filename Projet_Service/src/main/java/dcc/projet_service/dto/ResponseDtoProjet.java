package dcc.projet_service.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResponseDtoProjet {

    private Long id;
    private String titre;
    private String description;
    private String status;
    private Long id_chercheur;
    private Long id_enseignant;
    private ResponseDtoChercheur chercheur;

}
