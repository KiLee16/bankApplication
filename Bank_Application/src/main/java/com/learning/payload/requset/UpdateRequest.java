package com.learning.payload.requset;

import javax.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author : Ki Beom Lee
 * @time : 2022. 3. 10.-오후 3:21:14
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRequest {
	@NotBlank
	private long customerId;
	@NotBlank
	private String fullname; 
	@NotBlank
	private String phone;
	@NotBlank
	private String pan; 
	@NotBlank
	private String aadhar;
	@NotBlank
	private String secretQuestion;
	@NotBlank
	private String secretAnswer;
	
	private byte[] panimage;
	private byte[] aarchar ;
}
