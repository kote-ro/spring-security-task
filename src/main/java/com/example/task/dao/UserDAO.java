package com.example.task.dao;

import com.example.task.model.User;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class UserDAO {
    private static final Map<Long, User> userMap = new HashMap<>();

    static{
        initUsers();
    }

    private static void initUsers() {
        User user1 = new User(101L,"Peter","Aerts","aerts@gmail.com");
        User user2 = new User(102L,"Ernesto","Hoost","hoost@gmail.com");
        User user3 = new User(103L,"Jerome","Le Banner","lebanner@gmail.com");

        userMap.put(user1.getId(), user1);
        userMap.put(user2.getId(), user2);
        userMap.put(user3.getId(), user3);
    }

    public User getUser(Long id){
        return userMap.get(id);
    }

    public User addUser(User user){
        userMap.put(user.getId(), user);
        return user;
    }

    public User updateUser(User user) {
        userMap.put(user.getId(), user);
        return user;
    }

    public void deleteUser(Long id) {
        userMap.remove(id);
    }

    public List<User> getAllUsers() {
        Collection<User> c = userMap.values();
        return new ArrayList<>(c);
    }
}
