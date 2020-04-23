package com.crunchify.controller;

/**
 *
 * @author Legend-nov
 */
public class personbean {
    private String name;
    private Integer age;
    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the age
     */
    public Integer getAge() {
        return age;
    }

    /**
     * @param age the age to set
     */
    public void setAge(Integer age) {
        this.age = age;
    }
    public personbean(){}
    public personbean(String name,Integer age){
    this.name = name;
    this.age = age;
    }
}
