package com.google.jopenpec.certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;

 
public class CRLVerifier {

	 
	public static void verifyCertificateCRLs(X509Certificate cert)
			throws CertificateVerificationException {
		try {
			List<String> crlDistPoints = getCrlDistributionPoints(cert);
			for (String crlDP : crlDistPoints) {
				X509CRL crl = downloadCRL(crlDP);
				if (crl.isRevoked(cert)) {
					throw new CertificateVerificationException(
							"The certificate is revoked by CRL: " + crlDP);
				}
			}
		} catch (Exception ex) {
			if (ex instanceof CertificateVerificationException) {
				throw (CertificateVerificationException) ex;
			} else {
				throw new CertificateVerificationException(
						"Can not verify CRL for certificate: " + 
						cert.getSubjectX500Principal());
			}
		}
	}

	/**
	 * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
	 */
	private static X509CRL downloadCRL(String crlURL) throws IOException,
			CertificateException, CRLException,
			CertificateVerificationException, NamingException {
		if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
				|| crlURL.startsWith("ftp://")) {
			X509CRL crl = downloadCRLFromWeb(crlURL);
			return crl;
		}  else {
			throw new CertificateVerificationException(
					"Can not download CRL from certificate " +
					"distribution point: " + crlURL);
		}
	}

	
	/**
	 * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
	 * http://crl.infonotary.com/crl/identity-ca.crl
	 */
	private static X509CRL downloadCRLFromWeb(String crlURL)
			throws MalformedURLException, IOException, CertificateException,
			CRLException {
		URL url = new URL(crlURL);
		InputStream crlStream = url.openStream();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
			return crl;
		} finally {
			crlStream.close();
		}
	}

	/**
	 * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
	 * extension in a X.509 certificate. If CRL distribution point extension is
	 * unavailable, returns an empty list. 
	 */
	public static List<String> getCrlDistributionPoints(
			X509Certificate cert) throws CertificateParsingException, IOException {
		byte[] crldpExt = cert.getExtensionValue(
				X509Extensions.CRLDistributionPoints.getId());
		ASN1InputStream oAsnInStream = new ASN1InputStream(
				new ByteArrayInputStream(crldpExt));
		
		ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
		DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
		byte[] crldpExtOctets = dosCrlDP.getOctets();
		
		ASN1InputStream oAsnInStream2 = new ASN1InputStream(
				new ByteArrayInputStream(crldpExtOctets));
		
		ASN1Primitive derObj2 = oAsnInStream2.readObject();
		CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
		List<String> crlUrls = new ArrayList<String>();
		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
			System.out.println(dp);
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
		}
		return crlUrls;
	}

}