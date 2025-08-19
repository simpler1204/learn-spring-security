package com.in28minutes.learnspringsecurity.resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    public static final List<Todo>
            TODOS = List.of(new Todo("in28minutes", "Learn AWS"),
            new Todo("in28minutes", "Learn AWS Certified"));
    private static final Logger log = LoggerFactory.getLogger(TodoResource.class);

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return TODOS;
    }

    @GetMapping("/users/{username}/todos")
    public List<Todo> retrieveTodosForSpecificUser(@PathVariable String username) {
        if(username.equals("in28minutes")) {
            return TODOS;
        }
        return null;
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        log.info("Create {} for {}", todo,username);
    }


}

record Todo(String username, String description){}
