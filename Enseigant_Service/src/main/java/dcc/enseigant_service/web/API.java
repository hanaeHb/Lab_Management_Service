package dcc.enseigant_service.web;

import dcc.enseigant_service.dto.RequestDtoEnseignant;
import dcc.enseigant_service.dto.ResponseDtoEnseignant;
import dcc.enseigant_service.entitie.Enseignant;
import dcc.enseigant_service.mappers.EnseignantMapper;
import dcc.enseigant_service.service.EnseignantServiceImpl;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("v1/enseignants")
public class API {

    private EnseignantServiceImpl enseignantService;
    private EnseignantMapper enseignantMapper;

    public API(EnseignantServiceImpl enseignantService, EnseignantMapper enseignantMapper) {

        this.enseignantService = enseignantService;
        this.enseignantMapper = enseignantMapper;
    }

    @PostMapping
    public ResponseEntity<ResponseDtoEnseignant> add(@RequestBody RequestDtoEnseignant requestDtoEnseignant){
        return ResponseEntity.ok(enseignantService.Create_Enseignant(requestDtoEnseignant));
    }

    @GetMapping
    public ResponseEntity<List<ResponseDtoEnseignant>> GetALL(){
        return ResponseEntity.ok(enseignantService.GetAll_Enseignant());
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResponseDtoEnseignant> Get_ByID(@PathVariable Long id){
        return ResponseEntity.ok(enseignantService.Get_EnseignantByID(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ResponseDtoEnseignant> Update(@PathVariable Long id, @RequestBody Enseignant enseignant){
        return ResponseEntity.ok(enseignantService.Update_Enseignant(enseignant,id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity Delete(@PathVariable Long id){
        enseignantService.Delete_Enseignant(id);
        return ResponseEntity.ok().build();
    }


    @GetMapping("/statistique/{id}")
    public ResponseEntity<Map<String,Long>> statistique(@PathVariable Long id){
        return  ResponseEntity.ok(enseignantService.statistique(id));
    }


    // utiliser dans login/ authentification de microservice-securité

    @GetMapping("/email/{email}")
    public ResponseEntity<Map<String,String>> getByemail(@PathVariable String email){

        ResponseDtoEnseignant enseignant = enseignantService.FindByEmail(email);
        if (enseignant!=null) {
            Map<String, String> infos_user = new HashMap<>();

            infos_user.put("email", enseignant.getEmail());
            infos_user.put("password", enseignant.getMotDePasse());
            infos_user.put("scope", "Enseignant");
            return ResponseEntity.ok(infos_user);
        }
        return ResponseEntity.notFound().build();
    }





}
