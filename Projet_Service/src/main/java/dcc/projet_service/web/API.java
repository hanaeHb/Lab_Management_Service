package dcc.projet_service.web;

import dcc.projet_service.client.ChercheurRestFeign;
import dcc.projet_service.dto.RequestDtoProjet;
import dcc.projet_service.dto.ResponseDtoProjet;
import dcc.projet_service.service.ProjetService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/projets")
public class API {

    private ProjetService projetService;
    private ChercheurRestFeign chercheurRestFeign;

    public API(ProjetService projetService, ChercheurRestFeign chercheurRestFeign) {
        this.projetService = projetService;
        this.chercheurRestFeign = chercheurRestFeign;
    }

    @PostMapping
    public ResponseEntity<ResponseDtoProjet> add(@RequestBody RequestDtoProjet projet){
        try {
            ResponseDtoProjet p = projetService.Create_Projet(projet);
            return ResponseEntity.ok(p);
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }


    @GetMapping
    public ResponseEntity<List<ResponseDtoProjet>> GetAll(){
        try {
            List<ResponseDtoProjet> projetList = projetService.GetAll_Projet();


            return ResponseEntity.ok(projetList);
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResponseDtoProjet> GetByID(@PathVariable Long id){
        try {
            ResponseDtoProjet projet = projetService.Get_ProjetById(id);
            return ResponseEntity.ok(projet);
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }


    @PutMapping("/{id}")
    public ResponseEntity<ResponseDtoProjet> update(@PathVariable Long id,@RequestBody RequestDtoProjet projet){
        try {
            ResponseDtoProjet p = projetService.Update_Projet(id, projet);
            return ResponseEntity.ok(p);
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }


    @DeleteMapping("/{id}")
    public ResponseEntity Delete(@PathVariable Long id){
        try {
            projetService.Delete_Projet(id);
            return ResponseEntity.ok().build();
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("Enseignant/{id}") // statistique sur projet.
    public ResponseEntity<Long> nb_projet_enseinant(@PathVariable Long id){
        try {
            long nombreDeProjetsParEnseignant = projetService.getNombreDeProjetsParEnseignant(id);
            return ResponseEntity.ok(nombreDeProjetsParEnseignant);
        }catch (Exception e){
            return ResponseEntity.internalServerError().build();
        }
    }



}
