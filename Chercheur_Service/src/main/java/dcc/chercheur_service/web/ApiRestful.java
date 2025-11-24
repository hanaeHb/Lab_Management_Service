package dcc.chercheur_service.web;
import dcc.chercheur_service.dto.RequestDtoChercheur;
import dcc.chercheur_service.dto.ResponseDtoChercheur;
import dcc.chercheur_service.entitie.Chercheur;
import dcc.chercheur_service.service.ChercheurService;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/v1/chercheurs")
public class ApiRestful {

    private ChercheurService chercheurService;

    public ApiRestful(ChercheurService chercheurService) {

        this.chercheurService = chercheurService;
    }

    @PostMapping
    public ResponseEntity<ResponseDtoChercheur> add(@RequestBody RequestDtoChercheur requestDtoChercheur){
        return ResponseEntity.ok(chercheurService.Create_Chercheur(requestDtoChercheur));
    }


    @GetMapping
    public ResponseEntity<List<ResponseDtoChercheur>> GetAll(){
        return ResponseEntity.ok(chercheurService.GetALL_Chercheur());
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResponseDtoChercheur> GetById(@PathVariable Long id){
        return ResponseEntity.ok(chercheurService.Get_ChercheurById(id));
    }


    @PutMapping("/{id}")
    public ResponseEntity<ResponseDtoChercheur> Update( @PathVariable Long id, @RequestBody RequestDtoChercheur chercheur){
        return ResponseEntity.ok(chercheurService.Update_Chercheur(id,chercheur));
    }

    @DeleteMapping("/{id}")
    public void Delete(@PathVariable Long id){
        chercheurService.Delete_Chercheur(id);
    }


    @GetMapping("Enseignant/{id}") // utiliser par enseignant pour statis.
    public ResponseEntity<Long> nb_chercheur_enseignant(@PathVariable Long id) {
        try {
            long nombreDeChercheurParEnseignant = chercheurService.getNombreDeChercheurParEnseignant(id);
            return ResponseEntity.ok(nombreDeChercheurParEnseignant);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
    @GetMapping("/email/{email}") // utiliser login
    public ResponseEntity<Map<String,String>> getByemail(@PathVariable String email){

        ResponseDtoChercheur chercheur = chercheurService.Get_ChercheurByEmail(email);
        if (chercheur!=null) {
            Map<String, String> infos_user = new HashMap<>();

            infos_user.put("email", chercheur.getEmail());
            infos_user.put("password", chercheur.getPassword());
            infos_user.put("scope", "Chercheur");
            return ResponseEntity.ok(infos_user);
        }
        return ResponseEntity.notFound().build();
    }


}
