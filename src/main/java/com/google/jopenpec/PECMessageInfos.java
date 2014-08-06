package com.google.jopenpec;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.w3c.dom.Document;

public class PECMessageInfos {
	private Set<X509Certificate> signatures;
	private Document certificate;
	private PECBodyParts bodyParts;

	public PECMessageInfos(Set<X509Certificate> signatures, Document certificate,
			PECBodyParts bodyParts) {
		this.signatures = signatures;
		this.certificate = certificate;
		this.bodyParts = bodyParts;

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
