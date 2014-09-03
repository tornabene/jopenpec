package com.google.jopenpec;

import java.util.List;

import org.w3c.dom.Document;

public class PECMessageInfos {
	private Document daticert;
	private PECBodyParts bodyParts;
	List<CertificateInfo> certificates;
	 
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
	
	public PECMessageInfos(List<CertificateInfo> certificates, Document daticert,
			PECBodyParts bodyParts,Boolean esito) {
		this.certificates = certificates;
		this.daticert = daticert;
		this.bodyParts = bodyParts;
		this.esito = esito;

	}

	public Document getDaticert() {
		return daticert;
	}

	public void setDaticert(Document daticert) {
		this.daticert = daticert;
	}

	public List<CertificateInfo> getCertificates() {
		return certificates;
	}

	public void setCertificates(List<CertificateInfo> certificates) {
		this.certificates = certificates;
	}

	public PECBodyParts getBodyParts() {
		return bodyParts;
	}

	public void setBodyParts(PECBodyParts bodyParts) {
		this.bodyParts = bodyParts;
	}

}
