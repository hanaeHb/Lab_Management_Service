package dcc.enseigant_service.repository;


import dcc.enseigant_service.entitie.Enseignant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EnseignantRepository extends JpaRepository<Enseignant, Long> {
    Enseignant findByEmail(String email); // utiliser pour login


}
