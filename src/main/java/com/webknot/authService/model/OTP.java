package com.webknot.authService.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "otp")
public class OTP {
    @Id
    @GeneratedValue()
    private Long id;
    String otp;

    @Enumerated(EnumType.STRING)
    OtpType otpType;

    @ManyToOne(cascade = CascadeType.DETACH)
    @JoinColumn(name = "consumer_id", referencedColumnName = "id")
    User consumerId;
    @ManyToOne(cascade = CascadeType.DETACH)
    @JoinColumn(name = "producer_id", referencedColumnName = "id")
    User producerId;

    @CreatedDate
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_at", nullable = false, updatable = false)
    private Date createdAt;

    @LastModifiedDate
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "updated_at")
    private Date updatedAt;
}
