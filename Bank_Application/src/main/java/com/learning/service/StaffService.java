package com.learning.service;

import java.util.List;
import java.util.Optional;

import com.learning.entity.UserDTO;




/**
 * @author : Ki Beom Lee
 * @time : 2022. 3. 8.-오후 4:31:17
 */
public interface  StaffService {

	
	public Optional<UserDTO> getUserById(long id);
	public List<UserDTO> getAllUsers();
	
	public boolean existsById(long id);
}