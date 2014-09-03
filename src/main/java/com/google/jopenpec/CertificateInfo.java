package com.google.jopenpec;

import java.io.Serializable;
import java.util.Date;

public class CertificateInfo implements Serializable {
	String soggetto;
	String rilasciato;
	String publicKey;
	Date daValidita;
	Date aValidita;
	CertificateInfo parent;
	
	public CertificateInfo getParent() {
		return parent;
	}

	public void setParent(CertificateInfo parent) {
		this.parent = parent;
	}

	public String getRilasciato() {
		return rilasciato;
	}

	public void setRilasciato(String rilasciato) {
		this.rilasciato = rilasciato;
	}

	public String getSoggetto() {
		return soggetto;
	}

	public void setSoggetto(String soggetto) {
		this.soggetto = soggetto;
	}


	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public Date getDaValidita() {
		return daValidita;
	}

	public void setDaValidita(Date daValidita) {
		this.daValidita = daValidita;
	}

	public Date getaValidita() {
		return aValidita;
	}

	public void setaValidita(Date aValidita) {
		this.aValidita = aValidita;
	}

	@Override
	public String toString() {
		return "CertificateInfo [soggetto=" + soggetto + ", rilasciato=" + rilasciato
				+ ", publicKey=" + publicKey + ", daValidita=" + daValidita
				+ ", aValidita=" + aValidita + "]";
	}

 

	
}
