package com.google.jopenpec;

import java.io.File;
import java.io.Serializable;
import java.net.URI;

public class FileInfo implements  Serializable{
	private File file;
	private String name;
	private URI url;
	
	public FileInfo(File attachment,String name) {
		this.file = attachment;
		this.name = name;
	}
	
	public File getFile() {
		return file;
	}
	public void setFile(File file) {
		this.file = file;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public URI getUrl() {
		return url;
	}
	public void setUrl(URI url) {
		this.url = url;
	}
	@Override
	public String toString() {
		return "FileInfo [file=" + file + ", name=" + name + ", url=" + url
				+ "]";
	}
	
	
}
