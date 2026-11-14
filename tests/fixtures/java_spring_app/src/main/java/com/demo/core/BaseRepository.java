package com.demo.core;

public abstract class BaseRepository implements Repository {
    protected void audit(String action) {
        System.out.println(action);
    }
}
