package com.dust.corp.keycloak.service.provider.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greetings")
public class GreetingController {

    @GetMapping("/home")
    public String home() {
        return "I'm at Home!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String greeting() {
        return "I'm SAML user!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMINS')")
    public String admin() {
        return "I'm SAML admin!";
    }

}
