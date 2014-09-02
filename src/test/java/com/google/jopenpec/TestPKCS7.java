package com.google.jopenpec;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

public class TestPKCS7 {

	
	

	@Test
	public void testOk2() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message-ok2.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert );
	 
		Assert.assertEquals("PEC VALIDA", info.getEsito() , true);
		
		for (X509Certificate c : info.getSignatures() ) {
			System.out.println("test2-------------" );
			System.out.println(c.getIssuerDN() );
		}
		
		System.out.println("info.getCertificate()-------------" +info.getCertificate());
		System.out.println("info.getEsito()-------------" +info.getEsito() );
		System.out.println("info.getSignatures()-------------" +info.getSignatures()  );
		
	}
	
	@Test
	public void testOk() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message_ok.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert );
	 
		Assert.assertEquals("PEC VALIDA", info.getEsito() , true);
		
		for (X509Certificate c : info.getSignatures() ) {
			System.out.println("test2-------------" );
			System.out.println(c.getIssuerDN() );
		}
		
		System.out.println("info.getCertificate()-------------" +info.getCertificate());
		
	}
	
	
	@Test
	public void testKo() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message_ko.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC(postacert );
		Assert.assertEquals("PEC NON VALIDA", info.getEsito() , false);
		
		
			if( info.getEsito()){
			for (X509Certificate c : info.getSignatures() ) {
				System.out.println("test2-------------" );
				System.out.println(c.getIssuerDN() );
				System.out.println(c.getSubjectDN()   );
			}
		}else
			System.out.println( info.getException().getMessage() );
			
		
	}
	 
}
