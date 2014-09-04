package com.google.jopenpec;

import java.util.List;

import org.w3c.dom.Document;

public class PECMessageInfos {
	private Document daticert;
	private PECMail pecMail;
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
			PECMail pecMail,Boolean esito) {
		this.certificates = certificates;
		this.daticert = daticert;
		this.pecMail = pecMail;
		this.esito = esito;

	}

	public Document getDaticert() {
		return daticert;
	}


	public List<CertificateInfo> getCertificates() {
		return certificates;
	}

 
  public PECMail getPecMail() {
	return pecMail;
}

}
