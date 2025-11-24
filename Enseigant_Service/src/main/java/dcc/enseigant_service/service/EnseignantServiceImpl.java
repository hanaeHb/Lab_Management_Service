package dcc.enseigant_service.service;



import dcc.enseigant_service.client.ChercheurRestFeign;
import dcc.enseigant_service.client.ProjetRestFeign;
import dcc.enseigant_service.dto.RequestDtoEnseignant;
import dcc.enseigant_service.dto.ResponseDtoEnseignant;
import dcc.enseigant_service.entitie.Enseignant;
import dcc.enseigant_service.mappers.EnseignantMapper;
import dcc.enseigant_service.repository.EnseignantRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class EnseignantServiceImpl {

    private EnseignantRepository enseignantRepository;
    private ChercheurRestFeign chercheurRestFeign;
    private ProjetRestFeign projetRestFeign;
    private EnseignantMapper enseignantMapper;
    private PasswordEncoder passwordEncoder;

    public EnseignantServiceImpl(EnseignantRepository enseignantRepository, ChercheurRestFeign chercheurRestFeign, ProjetRestFeign projetRestFeign, EnseignantMapper enseignantMapper, PasswordEncoder passwordEncoder) {
        this.enseignantRepository = enseignantRepository;
        this.chercheurRestFeign = chercheurRestFeign;
        this.projetRestFeign = projetRestFeign;
        this.enseignantMapper = enseignantMapper;
        this.passwordEncoder = passwordEncoder;
    }


    public ResponseDtoEnseignant Create_Enseignant(RequestDtoEnseignant e){
        Enseignant entity = enseignantMapper.toEntity(e);
        entity.setMotDePasse(passwordEncoder.encode(entity.getMotDePasse()));
        return enseignantMapper.toDto(enseignantRepository.save(entity));
    }

    public List<ResponseDtoEnseignant> GetAll_Enseignant(){
        return enseignantRepository.findAll()
                .stream()
                .map(enseignantMapper::toDto)
                .collect(Collectors.toList());
    }

    public ResponseDtoEnseignant Get_EnseignantByID(Long id){
        Enseignant enseignant = enseignantRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Enseignant non trouvé"));
        return enseignantMapper.toDto(enseignant);
    }

    public ResponseDtoEnseignant FindByEmail(String email){
        return enseignantMapper.toDto(enseignantRepository.findByEmail(email));
    }

    public ResponseDtoEnseignant Update_Enseignant(Enseignant req, Long id){
        Enseignant enseignant = enseignantRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Enseignant non trouvé"));

        if (req.getNom() != null) enseignant.setNom(req.getNom());
        if (req.getPrenom() != null) enseignant.setPrenom(req.getPrenom());
        if (req.getCne() != null) enseignant.setCne(req.getCne());
        if (req.getEmail() != null) enseignant.setEmail(req.getEmail());
        if (req.getMotDePasse() != null) enseignant.setMotDePasse(req.getMotDePasse());
        if (req.getThematiqueRecherche() != null) enseignant.setThematiqueRecherche(req.getThematiqueRecherche());

        return enseignantMapper.toDto(enseignantRepository.save(enseignant));

    }

    public void Delete_Enseignant(Long id){
        enseignantRepository.deleteById(id);
    }



    public Map<String,Long> statistique(Long id){

        Long nb_chercheur = chercheurRestFeign.nb_chercheur_Enseignant(id);
        Long nb_projet = projetRestFeign.nb_Projet_Enseignant(id);

        Map<String, Long> Statistiques = new HashMap<>();
        Statistiques.put("nombre de projet",nb_projet);
        Statistiques.put("nombre de chercheur",nb_chercheur);
        return  Statistiques;
    }



}
