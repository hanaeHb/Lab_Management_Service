package dcc.projet_service.mapper;


import dcc.projet_service.dto.RequestDtoProjet;
import dcc.projet_service.dto.ResponseDtoProjet;
import dcc.projet_service.entitie.Projet;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class ProjetMapper {

    public Projet toEntity(RequestDtoProjet dto) {
        Projet entity = new Projet();
        BeanUtils.copyProperties(dto, entity);
        return entity;
    }

    public ResponseDtoProjet toDto(Projet entity) {
        ResponseDtoProjet dto = new ResponseDtoProjet();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }

}
