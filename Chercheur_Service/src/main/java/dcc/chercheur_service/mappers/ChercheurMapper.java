package dcc.chercheur_service.mappers;
import dcc.chercheur_service.dto.RequestDtoChercheur;
import dcc.chercheur_service.dto.ResponseDtoChercheur;
import dcc.chercheur_service.entitie.Chercheur;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class ChercheurMapper {

    public Chercheur toEntity(RequestDtoChercheur dto) {
        Chercheur entity = new Chercheur();
        BeanUtils.copyProperties(dto, entity);
        return entity;
    }

    public ResponseDtoChercheur toDto(Chercheur entity) {
        ResponseDtoChercheur dto = new ResponseDtoChercheur();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }
}
