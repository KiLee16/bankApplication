package com.learning.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.learning.entity.AccountDTO;
import com.learning.entity.BeneficiaryDTO;
import com.learning.entity.Transaction;
import com.learning.entity.UserDTO;
import com.learning.enums.Active;
import com.learning.enums.Approved;
import com.learning.enums.CreditDebit;
import com.learning.enums.ERole;
import com.learning.enums.EStatus;
import com.learning.exceptions.IdNotFoundException;
import com.learning.exceptions.TransactionInvalidException;
import com.learning.exceptions.UnauthrorizedException;
import com.learning.jwt.JwtUtils;
import com.learning.payload.requset.SigninRequest;
import com.learning.payload.requset.StaffApproveBeneficiaryRequest;
import com.learning.payload.requset.TransferRequestStaff;
import com.learning.payload.response.JwtResponse;
import com.learning.payload.response.StaffAccountApproveResponse;
import com.learning.payload.response.StaffGetBeneficiaryResponse;
import com.learning.payload.response.StaffGetCustomerByIdResponse;
import com.learning.payload.response.StaffGetCustomerResponse;
import com.learning.payload.response.StaffUserEnabledDIsabledResponse;
import com.learning.payload.response.UnapprovedBeneficiariesResponse;
import com.learning.repo.BeneficiaryRepo;
import com.learning.security.service.UserDetailsImpl;
import com.learning.service.AccountService;
import com.learning.service.BeneficiaryService;
import com.learning.service.StaffService;
import com.learning.service.UserService;
import com.learning.service.impl.RoleServiceImpl;
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/staff")
public class StaffController {
	@Autowired
	UserService userService;
	@Autowired
	StaffService staffService;

	@Autowired
	AccountService accountService;

	@Autowired
	BeneficiaryService beneficiaryService;

	@Autowired
	BeneficiaryRepo beneficiaryRepo;

	@Autowired
	private AuthenticationManager authenticationManager;



	@Autowired
	private JwtUtils jwtUtils;

	@PostMapping("/authenticate")
	public ResponseEntity<?> signinStaff(@Valid @RequestBody SigninRequest signinRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(signinRequest.getUsername(), signinRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtUtils.generateToken(authentication);
		// get user data/ principal

		UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();

		List<String> roles = userDetailsImpl.getAuthorities().stream().map(e -> e.getAuthority())
				.collect(Collectors.toList());
		// return new token
		boolean isadmin = false;
		for (int i = 0; i < roles.size(); i++) {
			if (roles.get(i).equals(ERole.ROLE_STAFF.name())) {
				isadmin = true;
			}
		}
		if (!isadmin) {
			throw new UnauthrorizedException("unauthorized access");
		}
		
		Optional<UserDTO> staff = staffService.getUserByUserName(userDetailsImpl.getUsername());
		if(staff.isEmpty()) {
			throw new UnauthrorizedException("unauthorized access");
		}
		if(staff.get().getStatus().equals(EStatus.DISABLED)) {
			throw new UnauthrorizedException("unauthorized access");
		}
		Map<String ,String > token = new HashMap();
		token.put("token", new JwtResponse(jwt).getToken());
		return ResponseEntity.status(200).body(new JwtResponse(jwt, userDetailsImpl.getId(), userDetailsImpl.getUsername(), roles));

	}

	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/account/{accountNo}")
	public ResponseEntity<?> getStatementOfAccount(@PathVariable("accountNo") Long accountNo) {
		AccountDTO response = accountService.getAccount(accountNo);

		return ResponseEntity.status(200).body(response);

	}

//	/josh is working on it 
	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/beneficiary")
	public ResponseEntity<?> getUnapprovedBeneficiaries() {

//		List<StaffGetAccountResponse> response = new ArrayList<>();
		List<BeneficiaryDTO> toBeApproved = beneficiaryService.getAllBeneficiaries();
		List<StaffGetBeneficiaryResponse> response = new ArrayList();
		for(int i = 0 ; i < toBeApproved.size() ; i++) {
			if(toBeApproved.get(i).getActive().equals(Active.NO)) {
				StaffGetBeneficiaryResponse bene = new StaffGetBeneficiaryResponse();
				bene.setApproved(toBeApproved.get(i).getActive());
				bene.setBeneficiaryAcNo(toBeApproved.get(i).getAccountNumber());
				bene.setFromCustomer(toBeApproved.get(i).getUserId());
				bene.setBeneficiaryAddedDate(toBeApproved.get(i).getAddedDate());
				response.add(bene);
			}
			
		}
		return ResponseEntity.status(200).body(response);

	}

	@PreAuthorize("hasRole('STAFF')")
	@PutMapping("/beneficiary/{beneficiaryId}")
	public ResponseEntity<?> getApprovedBeneficiary(@PathVariable("beneficiaryId") Long beneficiaryId) {

//		Boolean benefiBoolean = beneficiaryRepo.existsById(beneficiaryId);
//		if (!benefiBoolean) {
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Sorry beneficiary not approved");
//		}

		BeneficiaryDTO beneficiaryToBeApproved = beneficiaryService.getBeneficiaryById(beneficiaryId);

		if (beneficiaryToBeApproved.getActive().equals(Active.NO)) {
			beneficiaryToBeApproved.setActive(Active.YES);
		} else {
			beneficiaryToBeApproved.setActive(Active.NO);
		}

		BeneficiaryDTO updated = beneficiaryService.updateBeneficiary(beneficiaryToBeApproved);
		StaffGetBeneficiaryResponse response = new StaffGetBeneficiaryResponse();
		response.setApproved(updated.getActive());
		response.setBeneficiaryAcNo(updated.getAccountNumber());
		response.setBeneficiaryAddedDate(updated.getAddedDate());
		response.setFromCustomer(updated.getUserId());
		
		return ResponseEntity.status(200).body(response);

	}
	@PreAuthorize("hasRole('STAFF')")
	@PutMapping("/beneficiary")
	public ResponseEntity<?> putApprovedBeneficiary(@RequestBody StaffApproveBeneficiaryRequest request) {
		
//		Boolean benefiBoolean = beneficiaryRepo.existsById(beneficiaryId);
//		if (!benefiBoolean) {
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Sorry beneficiary not approved");
//		}
		System.out.println(request.toString());
		StaffGetBeneficiaryResponse response = new StaffGetBeneficiaryResponse();
		UserDTO customer = userService.getUser(request.getFromCustomer());
		
		Set <BeneficiaryDTO> customerBens = customer.getBeneficiaries();
		
		customerBens.stream().forEach(
				ben -> {
					if(ben.getAccountNumber().equals(request.getBeneficiaryAcNo())) {
						
						if (ben.getActive().equals(Active.NO)) {
							ben.setActive(Active.YES);
						} else {
							ben.setActive(Active.NO);
						}
						response.setApproved(ben.getActive());
						response.setBeneficiaryAcNo(ben.getAccountNumber());
						response.setBeneficiaryAddedDate(ben.getAddedDate());
						response.setFromCustomer(ben.getUserId());
						
					}
				}
				);
		
//		(b -> b.getAccountNumber().equals(request.getBeneficiaryAcNo()));

		customer.setBeneficiaries(customerBens);
		
		userService.updateUser(customer);
		
//		
//		for(BeneficiaryDTO ben : customerBens) {
//			if(ben.getAccountNumber().equals(request.getBeneficiaryAcNo())) {
//				
//			}
//		}
//		
//		BeneficiaryDTO beneficiaryToBeApproved = beneficiaryService.getBeneficiaryById(beneficiaryId);
//		
//		if (beneficiaryToBeApproved.getActive().equals(Active.NO)) {
//			beneficiaryToBeApproved.setActive(Active.YES);
//		} else {
//			beneficiaryToBeApproved.setActive(Active.NO);
//		}
		
//		BeneficiaryDTO updated = beneficiaryService.updateBeneficiary(beneficiaryToBeApproved);
	
	
		
		return ResponseEntity.status(200).body(response);
		
	}

	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/accounts/approve")
	public ResponseEntity<?> getUnapprovedAccounts() {

		// no impl yet
		return ResponseEntity.ok(accountService.getToBeApproved());
	}
//	@GetMapping("/accounts")
//	public ResponseEntity<?> getAllAccounts() {
//		
//		
//	
//				List<AccountDTO> accounts = accountService.getAllAcounts();
//				List<StaffGetAllAccountsResponse> response = new ArrayList<>();
//				
//				for(AccountDTO acc : accounts) {
//					
//					
//				}
//				response.setAccNo(beneficiaries.get(i).getAccountNumber());
//				response.setAccType(beneficiaries.get(i).getAccountType());
//				response.setApproved(beneficiaries.get(i).getActive());
//				response.setCustomerName(beneficiaries.get(i).getName());
//				response.setDateCreated(beneficiaries.get(i).getAddedDate());
//				responses.add(response);
//				
//			
//			
//		}
//		
//		
//		
//		return ResponseEntity.status(200).body(responses);
//	}

	@PreAuthorize("hasRole('STAFF') " )
	@PutMapping("/accounts/approve/{accountId}")
	public ResponseEntity<?> approveAccount(@PathVariable("accountId") Long accountId) {
		AccountDTO account = accountService.getAccount(accountId);

		if (account.getApproved().equals(Approved.NO)) {
			account.setApproved(Approved.YES);

		} 

		AccountDTO updatedAccount = accountService.updateAccount(account);
		
		UserDetailsImpl staffDetails = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		StaffAccountApproveResponse response = new StaffAccountApproveResponse(); 
		response.setAccNo(updatedAccount.getAccountNumber());
		response.setAccType(updatedAccount.getAccountType());
		response.setApproved(updatedAccount.getApproved());
		Optional<UserDTO> user = userService.getUserById(updatedAccount.getCustomerId());
		if(user.isEmpty()) {
			return ResponseEntity.status(403).body("Approving of account was not successful");
		}
		response.setCustomerName(user.get().getFullname());
		response.setStaffUserName(staffDetails.getUsername());
		response.setDateCreated(updatedAccount.getDateOfCreation());
		return ResponseEntity.ok(response);
	}

//
	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/customer")
	public ResponseEntity<?> getAllCustomers() {
		
		List<StaffGetCustomerResponse> list = new ArrayList (); 
		List<UserDTO> users = staffService.getAllCustomers();
		for(int i = 0 ; i < users.size() ; i++) {
			StaffGetCustomerResponse response = new StaffGetCustomerResponse();
			response.setCustomerId(users.get(i).getId());
			response.setCustomerName(users.get(i).getFullname());
			response.setStatus(users.get(i).getStatus());
			list.add(response);
		}
		return ResponseEntity.status(200).body(list);
	}

// not sure how to pick enabled or disabled - Ki 
	@PreAuthorize("hasRole('STAFF')")
	@PutMapping("/{customerId}")
	public ResponseEntity<?> setCustomerEnabledDisabled(@PathVariable("customerId") Long customerId) {
		UserDTO user = userService.getUser(customerId);
		if(user.getStatus().equals(EStatus.DISABLED)) {
			user.setStatus(EStatus.ENABLE);
		} else {
		user.setStatus(EStatus.DISABLED);
		}
		UserDTO updated = userService.updateUser(user, user.getId());
		StaffUserEnabledDIsabledResponse response = new StaffUserEnabledDIsabledResponse();
		response.setCustomerId(updated.getId());
		response.setStatus(updated.getStatus());
		return ResponseEntity.status(200).body(response);
	}

	

	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/customer/{customerID}")
	public ResponseEntity<?> getCustomer(@PathVariable("customerID") Long customerId) {
		StaffGetCustomerByIdResponse response = new StaffGetCustomerByIdResponse(); 
		Optional<UserDTO> userExist = userService.getUserById(customerId);
		if(userExist.isEmpty()) {
			throw new IdNotFoundException("Customer Not Found");
		}
		UserDTO user = userExist.get();
		response.setCreated(user.getDateCreated());
		response.setCustomerId(user.getId());
		response.setCustomerName(user.getFullname());
		response.setStatus(user.getStatus());
		return ResponseEntity.status(200).body(response);
	}

	//@PreAuthorize("hasRole('STAFF')")
	@PutMapping("/transfer")
	public ResponseEntity<?> staffTransfer(@RequestBody TransferRequestStaff request) {

		Optional<AccountDTO> accountFrom = accountService.findAccountById(request.getFromAccNumber());
		Optional<AccountDTO> toAccount = accountService.findAccountById(request.getToAccNumber());
		Double amount = request.getAmount();
		String reason = request.getReason();
		if (accountFrom.isEmpty() || toAccount.isEmpty()) {
			throw new TransactionInvalidException("from " + request.getFromAccNumber() + " to "
					+ request.getToAccNumber() + " Account Number Not Valid");
		}
		if (!userService.userExistsById(accountFrom.get().getCustomerId())) {
			throw new TransactionInvalidException("from " + request.getFromAccNumber() + " to "
					+ request.getToAccNumber() + " Account Number Not Valid");
		}
		AccountDTO from = accountFrom.get();
		AccountDTO to = toAccount.get();

		// temp for accountFrom
		AccountDTO temp = from;
		
		request.setReason("Transfer was made by Bank agent: "+request.getStaff()+". "+request.getReason());

		temp.setAccountBalance(from.getAccountBalance() - amount);

		Transaction transaction = new Transaction();
		transaction.setDateTime(LocalDateTime.now());
		transaction.setReference(request.getReason());
		transaction.setAmount(request.getAmount());
		transaction.setType(CreditDebit.CREDIT);
		Set<Transaction> transactions = temp.getTransactions();
		transactions.add(transaction);
		temp.setTransactions(transactions);
		accountService.updateAccount(from.getAccountNumber(), temp);
System.out.println("Staff is: "+request.getStaff());
		AccountDTO temp2 = to;
		temp2.setAccountBalance(temp2.getAccountBalance() + amount);

		Transaction transaction2 = new Transaction();
		transaction2.setDateTime(LocalDateTime.now());
		transaction2.setReference(request.getReason());
		transaction2.setAmount(request.getAmount());
		transaction2.setType(CreditDebit.DEBIT);
		Set<Transaction> transactions2 = temp2.getTransactions();
		transactions2.add(transaction2);
		temp2.setTransactions(transactions2);
		accountService.updateAccount(to.getAccountNumber(), temp2);

		return ResponseEntity.status(200).body("transfer successs");
	}


}
