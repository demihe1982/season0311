package cn.dyan.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @RequestMapping("/")
    public String index(){
        return "Wellcome!";
    }

    @RequestMapping("/admin")
    public String admin(){
        return "Wellcome,admin!";
    }

    @RequestMapping("/user")
    public String user(){
        return "Wellcome,user!";
    }
}
