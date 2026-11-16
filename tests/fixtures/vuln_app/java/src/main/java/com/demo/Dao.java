package com.demo;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Dao {
    public ResultSet find(Connection conn, String name) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public Process run(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }

    public Object load(ObjectInputStream in) throws Exception {
        return in.readObject();
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
