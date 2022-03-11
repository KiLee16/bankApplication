package com.learning.controller;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.learning.entity.Role;
import com.learning.entity.StaffDTO;
import com.learning.enums.ERole;
import com.learning.exceptions.RoleNotFoundException;
import com.learning.jwt.JwtUtils;
import com.learning.payload.requset.SigninRequest;
import com.learning.payload.requset.StaffSignupRequeset;
import com.learning.payload.response.JwtResponse;
import com.learning.security.service.UserDetailsImpl;
import com.learning.service.impl.AdminServiceImpl;
import com.learning.service.impl.RoleServiceImpl;
import com.learning.service.impl.StaffServiceImpl;

/**
 * @author : Ki Beom Lee
 * @time : 2022. 3. 11.-오후 4:43:52
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtils jwtUtils;
	@Autowired
	private RoleServiceImpl roleService;
	@Autowired
	private AdminServiceImpl adminService ;
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> signin(@Valid @RequestBody SigninRequest signinRequest) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(signinRequest.getUserName(), signinRequest.getPassword()));

		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		String jwt = jwtUtils.generateToken(authentication);
		// get user data/ principal
	
		UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();

		List<String> roles = userDetailsImpl.getAuthorities().stream().map(e -> e.getAuthority())
				.collect(Collectors.toList());
		// return new token
		return ResponseEntity.status(200)
				.body(new JwtResponse(jwt, userDetailsImpl.getId(), userDetailsImpl.getUsername(), roles));

	}
	
	@PostMapping("/staff")
	public ResponseEntity<?> createStaff(@Valid @RequestBody StaffSignupRequeset request) {
		StaffDTO staff = new StaffDTO();
		staff.setFullname(request.getStaffFullName());
		staff.setUsername(request.getStaffUserName());
		staff.setPassword(passwordEncoder.encode(request.getStaffPassword()));

		Role role = roleService.getRoleName(ERole.ROLE_STAFF)
				.orElseThrow(() -> new RoleNotFoundException("this role has not found"));
		Set<Role> roles = new HashSet<>();
		roles.add(role);
		staff.setRoles(roles);
		adminService.addStaff(staff);
		return ResponseEntity.status(200).body("staff added");

	}
	
	@GetMapping("/staff")
	public ResponseEntity<?> getAllStaff() {
		List<StaffDTO> staffs = new ArrayList<>();
		staffs = adminService.getAllStaff();
		return ResponseEntity.status(200).body(staffs);

	}
	
}