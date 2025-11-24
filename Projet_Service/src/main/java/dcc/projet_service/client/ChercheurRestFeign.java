package dcc.projet_service.client;


import dcc.projet_service.configuration.FeignClientConfig;
import dcc.projet_service.dto.ResponseDtoChercheur;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
@FeignClient(name = "CHERCHEUR-SERVICE", configuration = FeignClientConfig.class)
public interface ChercheurRestFeign {

    @GetMapping("v1/chercheurs/{id}")
    ResponseDtoChercheur GetChercheurByID(@PathVariable Long id);

}
