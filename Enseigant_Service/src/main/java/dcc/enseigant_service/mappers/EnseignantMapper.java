package dcc.enseigant_service.mappers;

import dcc.enseigant_service.dto.RequestDtoEnseignant;
import dcc.enseigant_service.dto.ResponseDtoEnseignant;
import dcc.enseigant_service.entitie.Enseignant;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;


@Component
public class EnseignantMapper {

    public Enseignant toEntity(RequestDtoEnseignant dto) {
        Enseignant enseignant = new Enseignant();
        BeanUtils.copyProperties(dto, enseignant);
        return enseignant;
    }

    public ResponseDtoEnseignant toDto(Enseignant enseignant) {
        ResponseDtoEnseignant dto = new ResponseDtoEnseignant();
        BeanUtils.copyProperties(enseignant, dto);
        return dto;
    }
}
