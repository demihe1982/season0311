package cn.dyan.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

public class CustomUserDetailService extends JdbcUserDetailsManager {
    public UserDetails loadUserByUsername(String username){
       return super.loadUserByUsername(username);
    }
}
