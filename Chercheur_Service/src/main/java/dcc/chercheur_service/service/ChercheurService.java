package dcc.chercheur_service.service;


import dcc.chercheur_service.client.EnseignantRestFeign;
import dcc.chercheur_service.dto.RequestDtoChercheur;
import dcc.chercheur_service.dto.ResponseDtoChercheur;
import dcc.chercheur_service.entitie.Chercheur;
import dcc.chercheur_service.mappers.ChercheurMapper;
import dcc.chercheur_service.repository.ChercheurRepository;
import feign.FeignException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ChercheurService {

    private ChercheurRepository chercheurRepository;
    private ChercheurMapper chercheurMapper;
    private EnseignantRestFeign enseignantRestFeign;
    private PasswordEncoder passwordEncoder;

    public ChercheurService(ChercheurRepository chercheurRepository, ChercheurMapper chercheurMapper, EnseignantRestFeign enseignantRestFeign, PasswordEncoder passwordEncoder) {
        this.chercheurRepository = chercheurRepository;
        this.chercheurMapper = chercheurMapper;
        this.enseignantRestFeign = enseignantRestFeign;
        this.passwordEncoder = passwordEncoder;
    }


    public ResponseDtoChercheur Create_Chercheur(RequestDtoChercheur requestDtoChercheur){

        // Vérifier que l'enseignant existe dans EnseignantService
        try {
            enseignantRestFeign.Enseignant_ByID(requestDtoChercheur.getIdEnseignant());
        } catch (FeignException.NotFound nf) {
            throw new IllegalArgumentException("L'enseignant n'est pas existe ");
        }
        Chercheur chercheur = chercheurMapper.toEntity(requestDtoChercheur);
        chercheur.setPassword(passwordEncoder.encode(chercheur.getPassword()));
        return chercheurMapper.toDto(chercheurRepository.save(chercheur));
    }


    public List<ResponseDtoChercheur> GetALL_Chercheur( ){
        return chercheurRepository.findAll().stream()
                .map(c -> { // récupérer Enseignant d chercheur (traitement optionnel)
                    c.setEnseignant(enseignantRestFeign.Enseignant_ByID(c.getIdEnseignant()));
                    return chercheurMapper.toDto(c);
                })
                .collect(Collectors.toList());

    }

    public ResponseDtoChercheur Get_ChercheurById( Long id){
        return chercheurRepository.findById(id)
                .map(chercheur -> {
                   chercheur.setEnseignant(enseignantRestFeign.Enseignant_ByID(chercheur.getIdEnseignant()));
                    return chercheurMapper.toDto(chercheur);
                })
                .orElseThrow(() -> new IllegalArgumentException("Chercheur non trouvé"));

    }


    public ResponseDtoChercheur Get_ChercheurByEmail(String email){
        Chercheur chercheur = chercheurRepository.findChercheurByEmail(email);
        return chercheurMapper.toDto(chercheur);
    }


    public ResponseDtoChercheur Update_Chercheur(Long id,RequestDtoChercheur dto){
        Chercheur entity = chercheurRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Chercheur non trouvé"));

        if (dto.getNom() != null) entity.setNom(dto.getNom());
        if (dto.getPrenom() != null) entity.setPrenom(dto.getPrenom());
        if (dto.getEmail() != null) entity.setEmail(dto.getEmail());
        if (dto.getPassword() != null) entity.setPassword(passwordEncoder.encode(dto.getPassword()));
        if (dto.getDomaineRecherche() != null) entity.setDomaineRecherche(dto.getDomaineRecherche());
        if (dto.getIdEnseignant() != null) entity.setIdEnseignant(dto.getIdEnseignant());

        return chercheurMapper.toDto(chercheurRepository.save(entity));
    }

    public void Delete_Chercheur(Long id){
        chercheurRepository.deleteById(id);
    }

    public long getNombreDeChercheurParEnseignant(Long id_enseignant) {
        return chercheurRepository.Nombre_chercheur_Enseignant(id_enseignant);
    }








}
