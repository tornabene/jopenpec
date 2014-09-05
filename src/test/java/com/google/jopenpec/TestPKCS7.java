package com.google.jopenpec;

import java.io.FileInputStream;

import org.junit.Assert;
import org.junit.Test;

public class TestPKCS7 {

	@Test
	public void testOsk2() throws Exception {
		FileInputStream postacert = new FileInputStream("mail/smime.p7s");
	}
	
	
	@Test
	public void testOk2() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message-ok2.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert,123L,"testaccount" );
	 
		Assert.assertEquals("PEC VALIDA", info.getEsito() , true);
//		
//		for (X509Certificate c : info.getSignatures() ) {
//			System.out.println("test2-------------" );
//			System.out.println(c.getIssuerDN() );
//		}
//		
		System.out.println("info.getCertificate()-------------" +info.getCertificates() );
		System.out.println("info.getEsito()-------------" +info.getEsito() );
		System.out.println("info.getSignatures()-------------" +info.getDaticert()   );
		
		System.out.println("info.getPecMail().getBody() -------------" +info.getPecMail().getBody()  );
			
		
//		
	}
	
	@Test
	public void testOk() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message_ok.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert ,1234L,"testaccount" );
	 
		Assert.assertEquals("PEC VALIDA", info.getEsito() , true);
		
		for (CertificateInfo c : info.getCertificates() ) {
			System.out.println("test2-------------" );
			System.out.println(c );
		}
		
	}
	
	
	@Test
	public void testKo() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message_ko.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC(postacert ,1237L,"testaccount");
		Assert.assertEquals("PEC NON VALIDA", info.getEsito() , false);
		
		
			if( info.getEsito()){
			for (CertificateInfo c : info.getCertificates()   ) {
				System.out.println("test2-------------" );
				System.out.println(c );
			}
		}else
			System.out.println( info.getException().getMessage() );
			
		
	}
	 
}
