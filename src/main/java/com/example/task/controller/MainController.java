package com.example.task.controller;

import com.example.task.dao.UserDAO;
import com.example.task.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class MainController {
    @Autowired
    private UserDAO userDAO;

    @RequestMapping("/")
    @ResponseBody
    public String welcome() {
        return "You are in my API :)";
    }

    @RequestMapping(value = "/users", method = RequestMethod.GET)
    @ResponseBody
    public List<User> getUsers() {
        List<User> list = userDAO.getAllUsers();
        return list;
    }

    @RequestMapping(value = "/users/{userId}", method = RequestMethod.GET)
    @ResponseBody
    public User getUser(@PathVariable("userId") Long userId) {
        return userDAO.getUser(userId);
    }

    @RequestMapping(value = "/user", method = RequestMethod.POST)
    @ResponseBody
    public User addUser(@RequestBody User user) {
        System.out.println("Creating user: "+user.getFirstName()+user.getSecondName());
        return userDAO.addUser(user);
    }

    @RequestMapping(value = "/user", method = RequestMethod.PUT)
    @ResponseBody
    public User updateUser(@RequestBody User user) {
        System.out.println("Updating user: "+user.getFirstName()+user.getSecondName());
        return userDAO.updateUser(user);
    }

    @RequestMapping(value = "/user/{userId}", method = RequestMethod.DELETE)
    @ResponseBody
    public void deleteUser(@PathVariable("userId") Long userId) {
        System.out.println("Deleting user with id: "+userId);
        userDAO.deleteUser(userId);
    }
}
