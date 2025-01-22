package com.dust.corp.keycloak.service.provider.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Represents the OAuthController class in the Keycloak_Service_Provider project.
 *
 * @author Kashan Asim
 * @version 1.0
 * @project Keycloak_Service_Provider
 * @module com.dust.corp.keycloak.service.provider.controller
 * @class OAuthController
 * @lastModifiedBy Kashan.Asim
 * @lastModifiedDate 1/22/2025
 * @license Licensed under the Apache License, Version 2.0
 * @description A brief description of the class functionality.
 * @notes <ul>
 * <li>Provide any additional notes or remarks here.</li>
 * </ul>
 * @since 1/22/2025
 */
@Controller
public class OAuthController {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String redirectUri;

    @GetMapping("/sample")
    public String home() {
        return "oauth-sample.html";
    }

    @GetMapping("/oauth/login")
    public String loginWithGoogle(@RequestParam Map<String, String> params, Model model) {
        String scopes = String.join(" ", params.values());
        String oauthUrl = String.format(
                "https://accounts.google.com/o/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&access_type=offline",
                clientId, redirectUri, scopes);
        model.addAttribute("oauthUrl", oauthUrl);
        return "redirect:" + oauthUrl;
    }

    @GetMapping("/oauth/callback")
    public ResponseEntity<?> handleCallback(@RequestParam("code") String code) {
        RestTemplate restTemplate = new RestTemplate();

        var request = Map.of(
                "code", code,
                "client_id", clientId,
                "client_secret", clientSecret,
                "redirect_uri", redirectUri,
                "grant_type", "authorization_code"
        );

        var response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token",
                request,
                Map.class
        );

        return ResponseEntity.ok(response.getBody());
    }
}
