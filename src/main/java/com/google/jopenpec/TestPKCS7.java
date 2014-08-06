package com.google.jopenpec;

import java.io.File;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestPKCS7 {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData sd = new CMSSignedData(new FileInputStream(
				args[0])); // new File(args[0])
		CertStore certs = sd.getCertificatesAndCRLs("Collection", "BC");
		SignerInformationStore sis = sd.getSignerInfos();
		System.out.println("getSignedContentTypeOID: "
				+ sd.getSignedContentTypeOID());
		Collection signerColl = sis.getSigners();
		for (Iterator signerIt = signerColl.iterator(); signerIt.hasNext();) {
			SignerInformation sinfo = (SignerInformation) signerIt.next();
			Collection certColl = certs.getCertificates(sinfo.getSID());
			for (Iterator certIt = certColl.iterator(); certIt.hasNext();) {
				/* THIS IS A CERTIFICATE FROM ONE OF THE SIGNERS */
				X509Certificate cert = (X509Certificate) certIt.next();
				X500Principal subject = cert.getSubjectX500Principal();
				System.out.println("Subject: " + subject);
				X500Principal issuer = cert.getSubjectX500Principal();
				System.out.println("Issuer: " + issuer);
			}
		}
	}
}
