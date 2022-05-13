package com.learning.controller;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.learning.apierrors.ApiError;
import com.learning.entity.AccountDTO;
import com.learning.entity.BeneficiaryDTO;
import com.learning.entity.Role;
import com.learning.entity.Transaction;
import com.learning.entity.UserDTO;
import com.learning.enums.AccountType;
import com.learning.enums.Active;
import com.learning.enums.Approved;
import com.learning.enums.CreditDebit;
import com.learning.enums.ERole;
import com.learning.enums.EStatus;
import com.learning.exceptions.AccountNotApprovedException;
import com.learning.exceptions.BalanceNonPositiveException;
import com.learning.exceptions.IdNotFoundException;
import com.learning.exceptions.RoleNotFoundException;
import com.learning.exceptions.SecretDetailsDoNotMatchException;
import com.learning.exceptions.TransactionInvalidException;
import com.learning.exceptions.UnauthrorizedException;
import com.learning.jwt.JwtUtils;
import com.learning.payload.requset.AccountRequest;
import com.learning.payload.requset.BeneficiaryPayload;
import com.learning.payload.requset.ForgotPasswordRequest;
import com.learning.payload.requset.SigninRequest;
import com.learning.payload.requset.SignupRequest;
import com.learning.payload.requset.TransferRequest;
import com.learning.payload.requset.UpdateRequest;
import com.learning.payload.response.AccountApproaval;
import com.learning.payload.response.AccountResponseEntity;
import com.learning.payload.response.AccountTransactionResponse;
import com.learning.payload.response.BeneficiaryAddedResponse;
import com.learning.payload.response.CustomerGetBeneficiaries;
import com.learning.payload.response.CustomerRegisterResponse;
import com.learning.payload.response.GetCustomerResponse;
import com.learning.payload.response.JwtResponse;
import com.learning.payload.response.UpdateResponse;
import com.learning.security.service.UserDetailsImpl;
import com.learning.service.AccountService;
import com.learning.service.StaffService;
import com.learning.service.UserService;
import com.learning.service.impl.BeneficiaryServiceImpl;
import com.learning.service.impl.RoleServiceImpl;

@CrossOrigin()
@RestController
@RequestMapping("/api/customer")
public class CustomerController {
	@Autowired
	UserService userService;
	@Autowired
	StaffService staffService;
	
//	@Autowired
//	AccountService accountService;
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtils jwtUtils;
	@Autowired
	private RoleServiceImpl roleService;
	@Autowired
	private AccountService accountService;  
	@Autowired
	private BeneficiaryServiceImpl beneficiaryService; 

	@PostMapping("/register")
	public ResponseEntity<?> createUser(@Valid @RequestBody SignupRequest signupRequest) {
		UserDTO user = new UserDTO();
		Role role = roleService.getRoleName(ERole.ROLE_CUSTOMER)
				.orElseThrow(() -> new RoleNotFoundException("this role has not found"));
		Set<Role> roles = new HashSet<>();
		roles.add(role);

		user.setUsername(signupRequest.getUserName());
		user.setFullname(signupRequest.getFullName());
		user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));

		user.setRoles(roles);
		user.setDateCreated(LocalDateTime.now());
		user.setStatus(EStatus.ENABLE);
		UserDTO newUser = userService.addUser(user);
		CustomerRegisterResponse response = new CustomerRegisterResponse();
		response.setCustomerId(newUser.getId());
		response.setFullName(newUser.getFullname());
		response.setPassword(newUser.getPassword());
		response.setUserName(newUser.getUsername());
		response.setDateCreated(newUser.getDateCreated());
		return ResponseEntity.status(201).body(response);

	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> signin(@Valid @RequestBody SigninRequest signinRequest) {
	
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(signinRequest.getUsername(), signinRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		String jwt = jwtUtils.generateToken(authentication);
		// get user data/ principal
	
		UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();

		List<String> roles = userDetailsImpl.getAuthorities().stream().map(e -> e.getAuthority())
				.collect(Collectors.toList());
		// return new token
		System.out.println(signinRequest);
		UserDTO user = userService.getUserById(userDetailsImpl.getId()).orElseThrow(() -> new IdNotFoundException("Id not found"));
		if(user.getStatus().equals(EStatus.DISABLED)) {
			throw new UnauthrorizedException("account is disabled");
		}
		

	
		Map<String ,String > token = new HashMap();
		token.put("token", new JwtResponse(jwt).getToken());
//		return ResponseEntity.status(200).body(token);

		return ResponseEntity.status(200).body(new JwtResponse(jwt, userDetailsImpl.getId(), userDetailsImpl.getUsername(), roles));


	}
	@PreAuthorize("hasRole('CUSTOMER')")
	@PostMapping("/{customerId}/account")
	public ResponseEntity<?> createAccount(@PathVariable("customerId") long customerId,
			@RequestBody AccountRequest request) {
		String type = request.getAccountType().name();
		AccountType roles = request.getAccountType();
		
		Approved approved = Approved.NO;
		if(request.getAccountBalance() < 0 && (!request.getAccountType().equals(AccountType.SB) || !request.getAccountType().equals(AccountType.CA))) {
		RuntimeException	response = new BalanceNonPositiveException("Account cannot be created");
			return ResponseEntity.status(403).body(response);
		}
		

		AccountDTO account = new AccountDTO();
		account.setAccountBalance(request.getAccountBalance());
		account.setAccountType(roles);
		account.setCustomerId(customerId);
		account.setApproved(approved);
		LocalDateTime now = LocalDateTime.now();
		account.setDateOfCreation(now);
		account.setEnableDisabled(EStatus.DISABLED);
//		double accNo = Math.random() * 100000000;
//		long roundAccNo = (long) accNo;
//		account.setAccountNumber(roundAccNo);
		UserDTO user = userService.getUserById(customerId).orElseThrow(() -> new IdNotFoundException("Id not found"));
		Set <AccountDTO> accounts = user.getAccount();
		accounts.add(account);
		user.setAccount(accounts);
		user = userService.updateUser(user, customerId);
		long id = 0 ; 
		for(AccountDTO e: accounts) {
			if( id < e.getAccountNumber()) {
				id = e.getAccountNumber();
				account = e;
			}
		}
		
		 
		AccountResponseEntity response = new AccountResponseEntity();
		response.setAccountBalance(account.getAccountBalance());
		response.setAccountNumber(account.getAccountNumber());
		response.setAccountType(account.getAccountType());
		response.setApproved(account.getApproved());
		response.setCustomerId(account.getCustomerId());
		response.setDateOfCreation(account.getDateOfCreation());
		return ResponseEntity.status(200).body(response);

	}

	@PreAuthorize("hasRole('STAFF')")
	@PutMapping("{customerId}/account/{accountNo}")
	public ResponseEntity<?> approveAccount(@PathVariable("customerId") long customerId,
			@PathVariable("accountNo") long accountNo, @RequestBody AccountRequest request) {
		// possibly user AccountRequest
		UserDTO user = staffService.getUserById(customerId).orElseThrow(() -> new IdNotFoundException("Please check Account Number"));
		Set<AccountDTO> accounts = user.getAccount();

		accounts.forEach(e -> {
			if (e.getAccountNumber() == accountNo) {
				e.setApproved(Approved.YES);

			}
		});

		user.setAccount(accounts);
		userService.updateUser(user, customerId);
		AccountApproaval response = new AccountApproaval();
		response.setAccountNumber(accountNo);
		accounts.forEach(e -> {
			if (e.getAccountNumber() == accountNo) {
				response.setAccountStatus(e.getApproved());

			}
		});

		return ResponseEntity.status(200).body(response);
	}
	@PreAuthorize("hasRole('CUSTOMER')")
	@GetMapping("{customerId}/account")
	public ResponseEntity<?> getAccounts(@PathVariable("customerId") long customerId) {
		Optional<UserDTO> data = userService.getUserById(customerId);
		if(data.isEmpty()) {
			throw new IdNotFoundException("Sorry Customer With " + customerId + " not found");
			
		}
		UserDTO user = data.get();
				Set<AccountDTO> accounts = user.getAccount();
		Set<AccountResponseEntity> responses = new HashSet<>();
		accounts.forEach(e -> {
			AccountResponseEntity response = new AccountResponseEntity();
			response.setAccountBalance(e.getAccountBalance());
			response.setAccountNumber(e.getAccountNumber());
			response.setAccountType(e.getAccountType());
			response.setApproved(e.getApproved());
			response.setCustomerId(e.getCustomerId());
			response.setDateOfCreation(e.getDateOfCreation());
			responses.add(response);

		});

		return ResponseEntity.status(200).body(responses);
	}
	@PreAuthorize("hasRole('CUSTOMER')")
	@PutMapping("/{customerId}")
	public ResponseEntity<?> updateCustomer(@PathVariable("customerId") long customerId,
			@Valid @ModelAttribute UpdateRequest request) {
		UserDTO user = new UserDTO();
		userService.getUserById(customerId).orElseThrow(() -> new IdNotFoundException("id not found"));
		user.setFullname(request.getFullname());
		user.setPhone(request.getPhone());
		user.setPan(request.getPan());
		user.setAadhar(request.getAadhar());
		user.setSecretQuestion(request.getSecretQuestion());
		user.setSecretAnswer(request.getSecretAnswer());
		
		try {
		
		      byte [] data = request.getAarchar().getBytes();
		    		  System.out.println(data);
			user.setPanimage(data);
			
		      byte [] data2 = request.getPanimage().getBytes();
//		     
			user.setAarchar(data2);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			 new FileNotFoundException("file not found");
		}
	     

		UserDTO updated = userService.updateUser(user, customerId);
		UpdateResponse response = new UpdateResponse();
		response.setCustomerId(updated.getId());
		response.setFullname(updated.getFullname());
		response.setPhone(updated.getPhone());
		response.setPan(updated.getPhone());
		response.setAadhar(updated.getAadhar());
		response.setSecretQuestion(updated.getSecretQuestion());
		response.setSecretAnswer(updated.getSecretAnswer());
		response.setPanimage(updated.getPanimage());
		response.setAarchar(updated.getPanimage());

		return ResponseEntity.status(200).body(response);

	}
	@PreAuthorize("hasRole('CUSTOMER')")
	@GetMapping("{customerId}")
	public ResponseEntity<?> getCustomer(@PathVariable("customerId") long customerId) {
		UserDTO user = userService.getUserById(customerId).orElseThrow(() -> new IdNotFoundException("Sorry Customer With " + customerId+ " not found"));
		GetCustomerResponse response = new GetCustomerResponse();
		response.setFullName(user.getFullname());
		response.setAadhar(user.getAadhar());
		response.setPan(user.getPan());
		response.setPhone(user.getPhone());
		response.setUsername(user.getUsername());
		
		return ResponseEntity.status(200).body(response);
	}

	@GetMapping("{customerId}/account/{accountid}")
	public ResponseEntity<?> getAccountFromId(@PathVariable("customerId") long customerId,
			@PathVariable("accountid") long accountid) {
		UserDTO user = userService.getUserById(customerId).orElseThrow(() -> new IdNotFoundException("Sorry customer With "+ customerId +" not found"));
		AccountDTO account = null;
		Iterator<AccountDTO> it = user.getAccount().iterator();
		while (it.hasNext()) {
			AccountDTO acc = it.next();
			if (acc.getAccountNumber() == accountid) {
				account = acc;
			}
		}
		if (account == null) {
			throw new IdNotFoundException("Id not found");
		}
		AccountTransactionResponse response = new AccountTransactionResponse();
		response.setAccountBalance(account.getAccountBalance());
		response.setAccountNumber(account.getAccountNumber());
		response.setAccountType(account.getAccountType());
		response.setEnabled(account.getEnableDisabled());
		response.setTransactions(account.getTransactions());
		return ResponseEntity.status(200).body(response);
	}


//	@PreAuthorize("hasRole('CUSTOMER')")

	@PreAuthorize("hasRole('CUSTOMER')")

	@GetMapping("{customerId}/beneficiary")
	public ResponseEntity<?> getBeneficiary(@PathVariable("customerId") long customerId) {
		System.out.println(customerId);
		List<CustomerGetBeneficiaries> response = userService.getCustomerBeneficiaries(customerId);
		return ResponseEntity.status(200).body(response);

	}
	//Make sure user has an account before adding beneficiary. or errors
//	@PreAuthorize("hasRole('CUSTOMER')")
	@PostMapping("{customerId}/beneficiary")
	public ResponseEntity<?> createBeneficiary(@PathVariable("customerId") Long customerId, @RequestBody BeneficiaryPayload payload) {
			Boolean userExists = userService.userExistsById(customerId);
		Boolean accountExists= accountService.accountExists(payload.getAccountNumber());
		if(!userExists ||!accountExists ) {
			throw new IdNotFoundException("Sorry Beneficiary With "+customerId +" not added");
		}
		

		
		if(accountExists) {
		BeneficiaryDTO ben = new BeneficiaryDTO();
//		System.out.println("Acc exists");
		
		ben.setAccountNumber(payload.getAccountNumber());
		Long beneficiaryAccountUserId = accountService.getAccountByAccountNumber((payload.getAccountNumber()))
				.getCustomerId();
		String beneficiaryName = userService.getUser(beneficiaryAccountUserId).getFullname();
		ben.setName(beneficiaryName);
		ben.setActive(Active.NO);
		 
		ben.setAccountType(payload.getAccountType());
//		String type = payload.getAccountType();
//		System.out.println(payload);
//		switch(type) {
//		case "SB": 
//			ben.setAccountType(AccountType.SB);
//		case "CA":
//			ben.setAccountType(AccountType.CA);
//		}
		ben.setAddedDate(LocalDateTime.now());
		ben.setUserId(customerId);
		
		UserDTO user =userService.getUser(customerId);
		Set<BeneficiaryDTO> userBeneficiaries = user.getBeneficiaries();
		userBeneficiaries.add(ben);
		user.setBeneficiaries(userBeneficiaries);
		UserDTO updatedUser=userService.updateUser(user, customerId);

		BeneficiaryAddedResponse response = new BeneficiaryAddedResponse();
		response.setActive(ben.getActive());
		response.setBeneficiaryAccountNo(ben.getAccountNumber());
		response.setBeneficiaryName(ben.getName());
		
		return ResponseEntity.status(200).body("Beneficiary with: "+payload.getAccountNumber() + "  added");
		}
		else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to add Beneficiary with "+payload.getAccountNumber());
					
		}

	}

	@PreAuthorize("hasRole('CUSTOMER')")
	@DeleteMapping("{customerId}/beneficiary/{beneficiaryId}")
	public ResponseEntity<?> deleteBeneficiary(@PathVariable("customerId") Long customerId,
			@PathVariable("beneficiaryId") Long beneficiaryId) {
		Boolean userExists = userService.userExistsById(customerId);
		
		BeneficiaryDTO beneficiary = beneficiaryService.getBeneficiaryById(beneficiaryId);
		
		if( !userExists || ! (beneficiary.getUserId()==customerId)) {
			
			throw new IdNotFoundException("Beneficiary Not Deleted");
		}
		
		UserDTO user = userService.getUser(customerId);
		
		Set <BeneficiaryDTO> userBens = user.getBeneficiaries();
//	not working 
//		userBens.removeIf(ben -> ben.getAccountNumber().equals(beneficiaryId) );
		userBens.remove(beneficiary);
		System.out.println("*******************" + userBens);
		user.setBeneficiaries(userBens);
		beneficiaryService.removeBeneficiaryByAccountNumber(beneficiaryId);
		UserDTO updatedUser = userService.updateUser(user);
		

		return ResponseEntity.status(200).body("Beneficiary Deleted Scuccessfully");

	}
	@PreAuthorize("hasRole('CUSTOMER')")
	@PutMapping("/transfer")
	public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest request) {
		UserDTO user = userService.getUserById(request.getCustomer())
				.orElseThrow(() -> new TransactionInvalidException("from " + request.getFromAccNumber() + " to "
						+ request.getToAccNumber() + " Account Number Not Valid"));
		AccountDTO accountFrom = accountService.getAccount(request.getFromAccNumber());
		AccountDTO toAccount = accountService.getAccount(request.getToAccNumber());
		if(accountFrom.getApproved()== Approved.NO || toAccount.getApproved() == Approved.NO) {
			throw new AccountNotApprovedException("from " + request.getFromAccNumber() + " to "
						+ request.getToAccNumber() + " Account Number Not Valid");
		}
		Double amount = request.getAmount();
		String reason = request.getReason();
		
		if(accountFrom.getCustomerId() != request.getCustomer()) {
			throw new TransactionInvalidException("from " + request.getFromAccNumber() + " to "
					+ request.getToAccNumber() + " Account Number Not Valid");
		}
		//temp for accountFrom 
		AccountDTO temp = accountFrom;
	
		temp.setAccountBalance(accountFrom.getAccountBalance() - amount);

		Transaction transaction = new Transaction();
		transaction.setDateTime(LocalDateTime.now());
		transaction.setReference(request.getReason());
		transaction.setAmount(request.getAmount());
		transaction.setType(CreditDebit.CREDIT);
		Set<Transaction> transactions = temp.getTransactions();
		transactions.add(transaction);
		temp.setTransactions(transactions);
		accountService.updateAccount(accountFrom.getAccountNumber(), temp);

		// deal with the uer to
		UserDTO toAccountHolder = userService.getUserById(toAccount.getCustomerId())
				.orElseThrow(() -> new TransactionInvalidException("from " + request.getFromAccNumber() + " to "
						+ request.getToAccNumber() + " Account Number Not Valid"));
		
		AccountDTO temp2 = toAccount;
		temp2.setAccountBalance(temp2.getAccountBalance() + amount);
	
		Transaction transaction2 = new Transaction();
		transaction2.setDateTime(LocalDateTime.now());
		transaction2.setReference(request.getReason());
		transaction2.setAmount(request.getAmount());
		transaction2.setType(CreditDebit.DEBIT);
		Set<Transaction> transactions2 = temp2.getTransactions();
		transactions2.add(transaction2);
		temp2.setTransactions(transactions2);
		accountService.updateAccount(toAccount.getAccountNumber(), temp2);
		
		
		return ResponseEntity.status(200).body("transaction Scuccessfully");

	}
//	@PreAuthorize("hasRole('CUSTOMER')")
//	@GetMapping("/{customerId}/forgot/question/answer")
//	public ResponseEntity<?> secretQuestionAnswer(@Valid @RequestBody TransferRequest request) {
//		
//		
//		return ResponseEntity.status(200).body("transaction Scuccessfully");
//
//	}
	
	
	
	
	// secret Question and Answer
//		
		@GetMapping("/{username}/forgot/question/answer")
		public ResponseEntity<?> secretQuestionAnswer(@PathVariable("username") String username,  @RequestBody ForgotPasswordRequest payload)   {
			
			//forgot.getUsername();
			System.out.println("test");
			UserDTO user =userService.findByUsername(username);//get user first
			
			if(user.getSecretAnswer().equalsIgnoreCase(payload.getSecurityAnswer()) ) {
				
				return ResponseEntity.status(200).body("Details Validated");
			}else {
				
				throw new SecretDetailsDoNotMatchException("Sorry your secret details are not matching");
			}
			
			

		}

		// password update
		@PutMapping("/{username}/forgot")
		public ResponseEntity<?> updatePassword(@RequestBody SigninRequest payload , @PathVariable("username") String username) {
//			payload.getUserName(); // get username
////			payload.getPassword(); // the new password
//
			System.out.println(payload.getUsername());
			if (userService.existsByUsername(payload.getUsername())) { // comparing the new password with the old one
				
				UserDTO user = userService.findByUsername(username);
				
				user.setPassword(passwordEncoder.encode(payload.getPassword()));
				
				userService.updateUser(user);
				return ResponseEntity.status(200).body("new password updated");
			} else {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Sorry password not updated");
			}
			
			
			
		}

}