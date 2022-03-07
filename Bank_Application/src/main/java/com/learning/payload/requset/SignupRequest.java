package com.learning.payload.requset;

import java.time.LocalDate;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.learning.enums.AccountType;
import com.learning.enums.ERole;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor

public class SignupRequest {
	// sign up request info in the payload
	/*
	 * @Id
	 * 
	 * @GeneratedValue(strategy = GenerationType.IDENTITY) private long customerId;
	 */
	@NotBlank
	private long accountNumber;
	@NotBlank
	private Double accountBalance;
	@NotBlank
	private String approveStatus;
	@JsonFormat(pattern = "MM-dd-yyyy")
	private LocalDate dateOfCreation;
	@NotEmpty
	private ERole roles; // role of type enum
	@NotEmpty
	private AccountType accountType; // accountType of type enum

}
