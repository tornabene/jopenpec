package com.google.jopenpec;

import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.Test;

public class TestPKCS7 {
	
	
	//@Test
	public  void test1() throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData sd = new CMSSignedData(new FileInputStream( "mail/nopec.eml") );
		verify(sd);
	}

	private void verify(CMSSignedData sd) {
		Store certs = sd.getCertificates()  ;
		SignerInformationStore sis = sd.getSignerInfos();
		System.out.println("getSignedContentTypeOID: "
				+ sd.getSignedContentTypeOID());
		
		Collection signerColl = sis.getSigners();
		for (Iterator signerIt = signerColl.iterator(); signerIt.hasNext();) {
			SignerInformation sinfo = (SignerInformation) signerIt.next();
			Collection certColl = certs.getMatches( sinfo.getSID() );
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
