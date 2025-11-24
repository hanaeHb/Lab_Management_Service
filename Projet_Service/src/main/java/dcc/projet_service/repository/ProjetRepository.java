package dcc.projet_service.repository;


import dcc.projet_service.entitie.Projet;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProjetRepository extends JpaRepository<Projet, Long> {
    @Query("SELECT COUNT(p) FROM Projet p WHERE p.id_enseignant = :enseignantId")
    long nombre_Projet_Enseignant(@Param("enseignantId") Long enseignantId);
}
