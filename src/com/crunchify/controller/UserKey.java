package com.crunchify.controller;
import java.security.PrivateKey;
import java.security.PublicKey;

public class UserKey {
	PrivateKey pri;
	PublicKey pub;
	PrivateKey newPri;
	PublicKey newPub;
	public PrivateKey getPri() {
		return pri;
	}
	public void setPri(PrivateKey pri) {
		this.pri = pri;
	}
	public PublicKey getPub() {
		return pub;
	}
	public void setPub(PublicKey pub) {
		this.pub = pub;
	}
	public PrivateKey getNewPri() {
		return newPri;
	}
	public void setNewPri(PrivateKey newPri) {
		this.newPri = newPri;
	}
	public PublicKey getNewPub() {
		return newPub;
	}
	public void setNewPub(PublicKey newPub) {
		this.newPub = newPub;
	}
	
	
}
