package com.dust.corp.keycloak.service.provider.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Objects;

@Controller
public class MainController {

    //    @GetMapping("/")
//    public String getPrincipal(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
//        String emailAddress = principal.getFirstAttribute("email");
//        model.addAttribute("emailAddress", emailAddress);
//        model.addAttribute("userAttributes", principal.getAttributes());
//        return "index-saml.html";
//    }

    @GetMapping("/")
    public String getIndex(Model model, Authentication auth) {
        model.addAttribute("name",
                auth instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidc
                        ? oidc.getPreferredUsername()
                        : "");
        model.addAttribute("isAuthenticated",
                auth != null && auth.isAuthenticated());
        model.addAttribute("isNice",
                auth != null && auth.getAuthorities().stream().anyMatch(authority -> {
                    return Objects.equals("NICE", authority.getAuthority());
                }));
        return "index.html";
    }

    @GetMapping("/nice")
    public String getNice(Model model, Authentication auth) {
        return "nice.html";
    }

//    @GetMapping("/me")
//    public UserInfoDto getGretting(JwtAuthenticationToken auth) {
//        return new UserInfoDto(
//                auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
//                auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
//    }
//
//    public static record UserInfoDto(String name, List roles) {
//    }

    @GetMapping(value = "/ping", produces = MimeTypeUtils.TEXT_PLAIN_VALUE)
    @ResponseBody
    public String ping() {
        return "pong!";
    }

//    @GetMapping(value = "/")
//    public ModelAndView getHome(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal,
//                                ModelMap model) {
//        if (principal != null) {
//            return new ModelAndView("redirect:/home.html", model);
//        }
//        return new ModelAndView("index", model);
//    }

    @GetMapping("/home.html")
    public String home(
            @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal,
            Model model
    ) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

}
