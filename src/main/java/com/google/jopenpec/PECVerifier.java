package com.google.jopenpec;

import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public final class PECVerifier {
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	Provider bcprov;
	JcaSimpleSignerInfoVerifierBuilder verifier;
	JcaX509CertificateConverter jcaX509CertificateConverter;

	public PECVerifier() {
		this.bcprov = Security.getProvider("BC");
		if (this.bcprov == null) {
			this.bcprov = new BouncyCastleProvider();
			Security.addProvider(bcprov);
		}

		this.verifier = new JcaSimpleSignerInfoVerifierBuilder();
		this.verifier.setProvider(bcprov);

		this.jcaX509CertificateConverter = new JcaX509CertificateConverter();
		this.jcaX509CertificateConverter.setProvider(bcprov);

		if (!Init.isInitialized()) {
			Init.init();
		}
	}

	private Set<X509Certificate> verifySignature(final SMIMESignedParser parser)
			throws Exception {
		final Set<X509Certificate> certificates = new HashSet<X509Certificate>();

		final Store certs = parser.getCertificates();
		verify(parser, certificates, certs);

		final Store crls = parser.getCRLs();
		verify(parser, certificates, crls);

		return certificates;
	}

	private void debugPring(SignerInformation castingSignerInformation2) {
		//System.out.println("------------>>castingSignerInformation:" + castingSignerInformation2.getSID().getIssuer());
		//System.out.println("------------>>getSubjectKeyIdentifier:"  + castingSignerInformation2.getSID().getSubjectKeyIdentifier());
	}

	private void verify(final SMIMESignedParser parser,
			final Set<X509Certificate> certificates, final Store store)
			throws CMSException, OperatorCreationException,
			CertificateException, Exception {
		final SignerInformationStore signerInfos = parser.getSignerInfos();
		final Collection<SignerInformation> signers = signerInfos.getSigners();
		for (SignerInformation signer : signers) {
			//System.out.println(" signer.getSID().getIssuer() :" 	+ signer.getSID().getIssuer());

			final Collection<X509CertificateHolder> certCollection = store
					.getMatches(signer.getSID());

			for (X509CertificateHolder x509CertificateHolder : certCollection) {

				SignerInformationVerifier singInfoVer = verifier
						.build(x509CertificateHolder);

				//System.out.println("singInfoVer--------------:" + singInfoVer);
				X509Certificate x509Certificate = jcaX509CertificateConverter
						.getCertificate(x509CertificateHolder);
				//System.out.println("x509Certificate:" + x509Certificate);

				x509Certificate.checkValidity();

				if (!signer.verify(singInfoVer)) {
					throw new Exception("signature invalid");
				}
				certificates.add(x509Certificate);
			}
		}
	}

	public PECMessageInfos verifyAnalizePEC(final InputStream imailstream ) {

		final Properties props = System.getProperties();
		final Session session = Session.getDefaultInstance(props, null);
		Document document = null;
		PECBodyParts bodyMessage = null;
		Boolean esito = false;
		Set<X509Certificate> signatures = null;
		try {
		final MimeMessage msg = new MimeMessage(session, imailstream);
	
			if (msg.isMimeType("multipart/signed")
					|| msg.isMimeType("application/pkcs7-mime")) {
				DigestCalculatorProvider digestCalProv = new BcDigestCalculatorProvider();
				final SMIMESignedParser s = new SMIMESignedParser(
						digestCalProv, (MimeMultipart) msg.getContent());

				document = extractDatiCertXML(s);
				bodyMessage = extractBodyMessage(s.getContent());
				signatures = verifySignature(s);

//				if ((bodyMessage.getBodyTextHTML() != null)
//						&& (bodyMessage.getBodyTextHTML().getInputStream() != null)) {
//					final InputStream istream = bodyMessage.getBodyTextHTML()
//							.getInputStream();
//					IOUtils.copy(istream, contenuto);
//				} else if ((bodyMessage.getBodyTextPlain() != null)
//						&& (bodyMessage.getBodyTextPlain().getInputStream() != null)) {
//					final InputStream istream = bodyMessage.getBodyTextPlain()
//							.getInputStream();
//
//				 IOUtils.copy(istream, contenuto);
//
//				}

				esito = true;

			} else {
				throw new Exception("NO Pec [" + msg.getContentType() + "]");
			}

			final PECMessageInfos docVer = new PECMessageInfos(signatures,
					document, bodyMessage, esito);
			return docVer;

		} catch (Exception e) {
			final PECMessageInfos docVer = new PECMessageInfos(signatures,
					document, bodyMessage, esito);
			docVer.setException(e);
			return docVer;
		}  

		

	}

	private PECBodyParts extractBodyMessage(final MimeBodyPart mimePart)
			throws Exception {
		final PECBodyParts bodyPartPieces = new PECBodyParts();
		final DataHandler data = mimePart.getDataHandler();
		final MimeMultipart multiPart = (MimeMultipart) data.getContent();
		for (int i = 0; i < multiPart.getCount(); i++) {
			final BodyPart bodyPiece = multiPart.getBodyPart(i);
			bodyPartPieces.putBodyPart(bodyPiece);
		}
		return bodyPartPieces;
	}

	private Document extractDatiCertXML(final SMIMESignedParser s)
			throws Exception {
		final MimeBodyPart mimePart = s.getContent();
		//System.out.println("mimePart:" + mimePart);
		final DataHandler data = mimePart.getDataHandler();
		//System.out.println("data:" + data);

		final MimeMultipart multiPart = (MimeMultipart) data.getContent();
		//System.out.println("multiPart:" + multiPart);

		if (multiPart.getCount() < 1) {
			throw new MessagingException("Missing attachments");
		}
		final BodyPart bodyCert = multiPart.getBodyPart(1);
		//System.out.println("bodyCert:" + bodyCert);

		final DataHandler dataCert = bodyCert.getDataHandler();
		//System.out.println("dataCert.getContent():" + dataCert.getContent());

		final DataSource dataSourceCert = dataCert.getDataSource();

		//System.out.println("dataSourceCert():" + dataSourceCert);

		final InputStream idataCert = dataSourceCert.getInputStream();

		final DocumentBuilderFactory builderFactory = DocumentBuilderFactory
				.newInstance();

		final DocumentBuilder parser = builderFactory.newDocumentBuilder();
		final InputSource source = new InputSource(idataCert);
		final Document domCert = parser.parse(source);
		return domCert;
	}
}
