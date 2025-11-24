package dcc.enseigant_service.client;

import dcc.enseigant_service.configuration.FeignClientConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "PROJET-SERVICE", configuration = FeignClientConfig.class)
public interface ProjetRestFeign {

    @GetMapping("v1/projets/Enseignant/{id}")
    Long nb_Projet_Enseignant(@PathVariable Long id);

}
