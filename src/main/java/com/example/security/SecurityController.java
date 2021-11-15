package com.example.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String home(){
        return "home";
    }

    @GetMapping("/login")
    public String loginPage(){
        return "loginPage";
    }
    
    @GetMapping("/denied")
    public String denied(){
        return "권한이 없습니다";
    }

    @GetMapping("/user")
    public String user(){
        return "userPage";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/admin/pay")
    public String payPage(){
        return "payPage";
    }

    @GetMapping("/admin/sys")
    public String sysPage(){
        return "sysPage";
    }


}
