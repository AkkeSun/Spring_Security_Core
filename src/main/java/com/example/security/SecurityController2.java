package com.example.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
@RequestMapping("/test2")
public class SecurityController2 {

    @GetMapping
    public String home(){
        return "test2 home";
    }

    @GetMapping("/loginContext")
    public Authentication context(HttpSession session){

        //-------SecurityContextHolder에서 꺼내기 -------
        // SecurityContext > Authentication > USER
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        //-------Session에서 꺼내기 -------
        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication sessionAuthentication = context.getAuthentication();

        return authentication;
    }
}
