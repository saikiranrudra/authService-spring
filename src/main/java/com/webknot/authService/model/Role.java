package com.webknot.authService.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue()
    private Long id;

    @Enumerated(EnumType.STRING)
    private ERole name;

    @PrePersist
    public void perPresist() {
        if(name == null) {
            name = ERole.ROLE_USER;
        }
    }
}
