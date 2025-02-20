package org.example.service;

import org.example.entities.UserInfo;
import org.example.entities.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUserDetails extends UserInfo implements UserDetails {

//    @Autowired
////    private UserDetailsService userDetailsService;

    private String username;

    private String password;

    Collection<? extends GrantedAuthority> authorities;


    public CustomUserDetails(UserInfo byUsername){
        this.username=byUsername.getUsername();
        this.password=byUsername.getPassword();
        List<GrantedAuthority> auths=new ArrayList<>();

        for(UserRole role:byUsername.getRoles()){
            auths.add(new SimpleGrantedAuthority(role.getName().toUpperCase()));
        }
    }


    public String getUsername(){
        return username;
    }

    public String getPassword(){
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
