package dcc.enseigant_service.client;

import dcc.enseigant_service.configuration.FeignClientConfig;
import lombok.Getter;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "CHERCHEUR-SERVICE", configuration = FeignClientConfig.class)
public interface ChercheurRestFeign {

    @GetMapping("v1/chercheurs/Enseignant/{id}")
    Long nb_chercheur_Enseignant(@PathVariable Long id);

}
