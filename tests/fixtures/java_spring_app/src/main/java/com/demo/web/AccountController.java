package com.demo.web;

import com.demo.core.AccountRepository;
import com.demo.core.Repository;
import java.lang.reflect.Method;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/accounts")
public class AccountController {
    private final Repository repository = AccountRepository.create();

    @GetMapping("/{id}")
    public String get(String id) {
        return format(repository.find(id));
    }

    @PostMapping("/actions")
    public Object action(String name) throws Exception {
        Method method = getClass().getMethod(name);
        return method.invoke(this);
    }

    private String format(String value) {
        return value.trim();
    }
}
