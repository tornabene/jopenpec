package com.google.jopenpec;

import java.io.File;
import java.io.FileInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.junit.Assert;
import org.junit.Test;
import org.openpec.domain.Postacert;

public class TestPKCS7 {

	@Test
	public void testOsk2() throws Exception {
		FileInputStream postacert = new FileInputStream("mail/smime.p7s");
 
		
	}
	
	

	
	@Test
	public void testdaticert() throws Exception {
		
		FileInputStream daticert = new FileInputStream("mail/daticert.xml");
		 
		JAXBContext jaxbContext = JAXBContext.newInstance(Postacert.class);
		 
		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		Postacert postacert = (Postacert) jaxbUnmarshaller.unmarshal(daticert);
	
		System.out.println("postacert.getIntestazione().getMittente():"+postacert.getIntestazione().getMittente());
		System.out.println("postacert.getIntestazione().getOggetto():"+postacert.getIntestazione().getOggetto() );
			
		Assert.assertEquals("PEC getMittente", postacert.getIntestazione().getMittente() , "tindaro.tornabene@pec.it");
	}
	@Test
	public void testOk2() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message-ok2.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert, new File ("testaccount/123")  );
	 
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
		System.out.println("info.getPecMail().getPostacert() -------------" +info.getPostacert()  );
			
		
	}
	
	@Test
	public void testOk() throws Exception {
		
		FileInputStream postacert = new FileInputStream("mail/message_ok.eml");
		 
		PECVerifier pecVerifier = new PECVerifier();
		PECMessageInfos info = pecVerifier.verifyAnalizePEC( postacert , new File ("testaccount/1234"));
	 
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
		PECMessageInfos info = pecVerifier.verifyAnalizePEC(postacert ,new File ("testaccount/1236"));
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
