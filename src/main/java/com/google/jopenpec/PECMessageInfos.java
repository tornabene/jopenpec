package com.google.jopenpec;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.w3c.dom.Document;

public class PECMessageInfos {
	private Set<X509Certificate> signatures;
	private Document certificate;
	private PECBodyParts bodyParts;
	
	private Exception exception;
	
	public Exception getException() {
		return exception;
	}

	public void setException(Exception exception) {
		this.exception = exception;
	}

	public Boolean getEsito() {
		return esito;
	}

	public void setEsito(Boolean esito) {
		this.esito = esito;
	}

	private Boolean esito;
	
	public PECMessageInfos(Set<X509Certificate> signatures, Document certificate,
			PECBodyParts bodyParts,Boolean esito) {
		this.signatures = signatures;
		this.certificate = certificate;
		this.bodyParts = bodyParts;
		this.esito = esito;

	}

	public Set<X509Certificate> getSignatures() {
		return signatures;
	}

	public void setSignatures(Set<X509Certificate> signatures) {
		this.signatures = signatures;
	}

	public Document getCertificate() {
		return certificate;
	}

	public void setCertificate(Document certificate) {
		this.certificate = certificate;
	}

	public PECBodyParts getBodyParts() {
		return bodyParts;
	}

	public void setBodyParts(PECBodyParts bodyParts) {
		this.bodyParts = bodyParts;
	}

}
