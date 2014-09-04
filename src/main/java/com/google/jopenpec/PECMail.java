package com.google.jopenpec;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class PECMail implements Serializable {
	private String uid;
	public String getUid() {
		return uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

	private Boolean hasAttachments;
	private String bodyType;
	private String body;
	private List<File> attachments = new ArrayList<File>();
	
	public final List<File> getAttachments() {
		return this.attachments;
	}

	public Boolean getHasAttachments() {
		return hasAttachments;
	}

	public void setHasAttachments(Boolean hasAttachments) {
		this.hasAttachments = hasAttachments;
	}

	public String getBodyType() {
		return bodyType;
	}

	public void setBodyType(String bodyType) {
		this.bodyType = bodyType;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}

	public void setAttachments(List<File> attachments) {
		this.attachments = attachments;
	}

}
