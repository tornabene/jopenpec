package com.google.jopenpec;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
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

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public final class PECVerifier {
	protected final Log logger = LogFactory.getLog(getClass());

	public PECVerifier() {
		Provider bcprov = Security.getProvider("BC");
		if (bcprov == null) {
			bcprov = new BouncyCastleProvider();
			Security.addProvider(bcprov);
		}

		if (!Init.isInitialized()) {
			Init.init();
		}
	}

	@SuppressWarnings("unchecked")
	private Set<Certificate> verify(final SMIMESignedParser s) throws Exception {
		final Set<Certificate> certificates = new HashSet<Certificate>();

		final Store certs = s.getCertificates();
		final SignerInformationStore signers = s.getSignerInfos();
		final Collection<SignerInformation> c = signers.getSigners();
		for (SignerInformation signer : c) {
			final Collection<X509Certificate> certCollection = certs.getMatches(signer.getSID());
			final X509Certificate cert =  certCollection.iterator().next();
			if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
				throw new Exception("signature invalid");
			}
			certificates.add(cert);
		}

		return certificates;
	}

	public PECMessageInfos verifyAnalizePEC(final InputStream imailstream,
			final OutputStream contenuto) throws Exception {
		final Properties props = System.getProperties();
		final Session session = Session.getDefaultInstance(props, null);
		Document document = null;
		PECBodyParts bodyMessage = null;
		Set<Certificate> signatures = null;
		final MimeMessage msg = new MimeMessage(session, imailstream);
		
		if (msg.isMimeType("multipart/signed")) {
			DigestCalculatorProvider digestCalProv = new BcDigestCalculatorProvider();
			final SMIMESignedParser s = new SMIMESignedParser( digestCalProv, (MimeMultipart) msg.getContent());
			
			document = PECVerifier.extractXMLCert(s);
			bodyMessage = PECVerifier.extractBodyMessage(s.getContent());
			signatures = verify(s);

			if ((bodyMessage.getBodyTextHTML() != null)
					&& (bodyMessage.getBodyTextHTML().getInputStream() != null)) {
				final InputStream istream = bodyMessage.getBodyTextHTML()
						.getInputStream();
				IOUtils.copy(istream, contenuto);
			} else if ((bodyMessage.getBodyTextPlain() != null)
					&& (bodyMessage.getBodyTextPlain().getInputStream() != null)) {
				final InputStream istream = bodyMessage.getBodyTextPlain()
						.getInputStream();
				IOUtils.copy(istream, contenuto);
			}

		} else {
			final String message = "MimeType unknown [" + msg.getContentType()
					+ "]";
			logger.info(message);
		}

		final PECMessageInfos docVer = new PECMessageInfos(signatures,document,bodyMessage);
		return docVer;

	}

	private static PECBodyParts extractBodyMessage(final MimeBodyPart mimePart)
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

	private static Document extractXMLCert(final SMIMESignedParser s)
			throws Exception {
		final MimeBodyPart mimePart = s.getContent();
		final DataHandler data = mimePart.getDataHandler();
		final MimeMultipart multiPart = (MimeMultipart) data.getContent();
		if (multiPart.getCount() < 1) {
			throw new MessagingException("Missing attachments");
		}
		final BodyPart bodyCert = multiPart.getBodyPart(1);
		final DataHandler dataCert = bodyCert.getDataHandler();
		final DataSource dataSourceCert = dataCert.getDataSource();
		final InputStream idataCert = dataSourceCert.getInputStream();
		final DocumentBuilderFactory builderFactory = DocumentBuilderFactory
				.newInstance();
		final DocumentBuilder parser = builderFactory.newDocumentBuilder();
		final InputSource source = new InputSource(idataCert);
		final Document domCert = parser.parse(source);
		return domCert;
	}
}
