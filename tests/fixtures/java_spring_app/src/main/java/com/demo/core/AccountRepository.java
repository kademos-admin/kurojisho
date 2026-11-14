package com.demo.core;

public class AccountRepository extends BaseRepository {
    public AccountRepository() {
    }

    @Override
    public String find(String id) {
        audit("find");
        return query("SELECT * FROM accounts WHERE id = '" + id + "'");
    }

    private String query(String sql) {
        return sql;
    }

    public static AccountRepository create() {
        return new AccountRepository();
    }
}
