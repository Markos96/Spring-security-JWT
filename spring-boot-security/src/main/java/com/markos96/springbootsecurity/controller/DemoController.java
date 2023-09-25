package com.markos96.springbootsecurity.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class DemoController {

    @PostMapping
    public String welcome(){
        return "Welcome from secure endpoint";
    }

}
