package dcc.chercheur_service.repository;


import dcc.chercheur_service.entitie.Chercheur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ChercheurRepository extends JpaRepository<Chercheur, Long> {

    Chercheur findChercheurByEmail(String email);

    @Query("SELECT COUNT(c) FROM Chercheur c WHERE c.idEnseignant = :enseignantId")
    long Nombre_chercheur_Enseignant(@Param("enseignantId") Long enseignantId);





}
