package com.geeksoverflow.security.azuread.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import com.geeksoverflow.security.azuread.database.dao.UserDAO;
import com.geeksoverflow.security.azuread.database.model.Role;
import com.geeksoverflow.security.azuread.database.model.User;
import com.microsoft.aad.adal4j.UserInfo;

/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 26/11/17
 */
public class RegisterUserDetailsService {

    @Autowired
    private UserDAO userDAO;


    @Transactional(value = "transactionManager")
    public void register(final UserInfo userInfo) {
        saveUser(buildUser(userInfo));
    }

    private void saveUser(final User user) {
        userDAO.save(user);
    }

    private User buildUser(final UserInfo userInfo) {
        Role adminRole = new Role();
        adminRole.setName("ADMIN");
        Role userRole = new Role();
        userRole.setName("USER");
        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        roles.add(userRole);
        return new User(userInfo.getUniqueId(),userInfo.getGivenName(),null,1,"AZUREAD",roles);
    }
}
