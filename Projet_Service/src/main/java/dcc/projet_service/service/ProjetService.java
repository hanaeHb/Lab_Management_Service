package dcc.projet_service.service;

import dcc.projet_service.client.ChercheurRestFeign;
import dcc.projet_service.dto.RequestDtoProjet;
import dcc.projet_service.dto.ResponseDtoProjet;
import dcc.projet_service.entitie.Projet;
import dcc.projet_service.mapper.ProjetMapper;
import dcc.projet_service.repository.ProjetRepository;

import feign.FeignException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
public class ProjetService {

    private  ProjetRepository projetRepository;
    private ChercheurRestFeign chercheurRestFeign;
    private ProjetMapper projetMapper;

    public ProjetService(ProjetRepository projetRepository, ChercheurRestFeign chercheurRestFeign, ProjetMapper projetMapper) {
        this.projetRepository = projetRepository;
        this.chercheurRestFeign = chercheurRestFeign;
        this.projetMapper = projetMapper;
    }

    public ResponseDtoProjet Create_Projet(RequestDtoProjet dto){
        // vérifier que le chercheur existe dans ChercheurService
        try {
            chercheurRestFeign.GetChercheurByID(dto.getId_chercheur());
        } catch (FeignException.NotFound nf) {
            throw new IllegalArgumentException("Le chercheur n'est pas existe ");
        }
        Projet projet = projetMapper.toEntity(dto);
        return projetMapper.toDto(projetRepository.save(projet));
    }


    public List<ResponseDtoProjet> GetAll_Projet(){

        return projetRepository.findAll().stream()
                .map(projet -> {
                    // récuperer le chercheur du projet optionnel
                    projet.setChercheur(chercheurRestFeign.GetChercheurByID(projet.getId_chercheur()));
                    return projetMapper.toDto(projet);
                })
                .toList();

    }

    public ResponseDtoProjet Get_ProjetById(Long id){
        Projet projet = projetRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Projet introuvable pour l'id fourni"));
        projet.setChercheur(chercheurRestFeign.GetChercheurByID(projet.getId_chercheur()));
        return projetMapper.toDto(projet);

    }

    public ResponseDtoProjet Update_Projet(Long id , RequestDtoProjet req){

        Projet projet = projetRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "projet non trouvé"));

        if (req.getDescription() != null) projet.setDescription(req.getDescription());
        if (req.getTitre() != null) projet.setTitre(req.getTitre());
        if (req.getStatus() != null) projet.setStatus(req.getStatus());
        if (req.getId_enseignant() != null) projet.setId_enseignant(req.getId_enseignant());
        if (req.getId_chercheur() != null) projet.setId_chercheur(req.getId_chercheur());

        return projetMapper.toDto(projetRepository.save(projet));

    }

    public void Delete_Projet(Long id){
        projetRepository.deleteById(id);
    }


    public long getNombreDeProjetsParEnseignant(Long id_enseignant) {
        return projetRepository.nombre_Projet_Enseignant(id_enseignant);
    }








}
