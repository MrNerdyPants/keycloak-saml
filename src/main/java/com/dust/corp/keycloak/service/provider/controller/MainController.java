package com.dust.corp.keycloak.service.provider.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class MainController {

//    @GetMapping("/")
//    public String getPrincipal(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
//        String emailAddress = principal.getFirstAttribute("email");
//        model.addAttribute("emailAddress", emailAddress);
//        model.addAttribute("userAttributes", principal.getAttributes());
//        return "index";
//    }

    @GetMapping(value = "/ping", produces = MimeTypeUtils.TEXT_PLAIN_VALUE)
    @ResponseBody
    public String ping() {
        return "pong!";
    }

    @GetMapping(value = "/")
    public ModelAndView getHome(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal,
                                ModelMap model){
        if( principal != null ) {
            return new ModelAndView("redirect:/home.html", model);
        }
        return new ModelAndView("index", model);
    }

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
