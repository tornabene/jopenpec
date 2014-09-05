package com.google.jopenpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
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
import org.apache.commons.mail.util.MimeMessageParser;
import org.apache.xml.security.Init;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
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
	DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

	private List<CertificateInfo> certificateChains(final SMIMESignedParser parser)
			throws CMSException, CertificateException, IOException,
			OperatorCreationException {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		SignerInformationStore signersInfoStore = parser.getSignerInfos();
		Collection<SignerInformation> signers = signersInfoStore.getSigners();

		Store store1 = parser.getCertificates();

		Iterator it = signersInfoStore.getSigners().iterator();

		List<CertificateInfo> chains  = new ArrayList<CertificateInfo>();
		
		if (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId sid = signer.getSID();
			Collection<X509CertificateHolder> holders = store1.getMatches(sid);

			for (X509CertificateHolder certholder : holders) {
				X509Certificate cert = jcaX509CertificateConverter
						.getCertificate(certholder);
				
				CertificateInfo first = new CertificateInfo();
				adattaCertificate(cert, first);
				certRecursive(chains, store1, certholder );
				chains.add(first);
				 
			}
		}
		return chains;
	}

	private void adattaCertificate(X509Certificate cert,
			CertificateInfo certInfo) {
		certInfo.setSoggetto(cert.getSubjectDN().getName());
		certInfo.setRilasciato(cert.getIssuerDN().getName());
		certInfo.setDaValidita(cert.getNotBefore());
		certInfo.setaValidita(cert.getNotAfter());
		certInfo.setPublicKey(cert.getPublicKey().toString());
	}

	private void certRecursive( List<CertificateInfo> chains ,
			Store store1, X509CertificateHolder certholder )
			throws CertificateException {
		AttributeCertificateHolder selec = new AttributeCertificateHolder(
				certholder.getIssuer());
		Collection<X509CertificateHolder> holdersd = store1.getMatches(selec);

		for (X509CertificateHolder certholder2 : holdersd) {
			X509Certificate c2 = jcaX509CertificateConverter
					.getCertificate(certholder2);
			CertificateInfo parent = new CertificateInfo();
			adattaCertificate(c2, parent);
			certRecursive(chains, store1, certholder2 );
			chains.add(parent);
		}
	}


	private List<CertificateInfo> verifySignature(final SMIMESignedParser parser)
			throws Exception {
		final Set<X509Certificate> certificates = new HashSet<X509Certificate>();

		final Store store = parser.getCertificates();
		verify(parser, certificates, store);

		final Store stores = parser.getCRLs();
		verify(parser, certificates, stores);

		List<CertificateInfo> certs = certificateChains(parser);
		return certs;
	}

	private void verify(final SMIMESignedParser parser,
			final Set<X509Certificate> certificates, final Store store)
			throws CMSException, OperatorCreationException,
			CertificateException, Exception {
		final SignerInformationStore signerInfos = parser.getSignerInfos();

		final Collection<SignerInformation> signers = signerInfos.getSigners();
		for (SignerInformation signer : signers) {

			final Collection<X509CertificateHolder> certCollection = store
					.getMatches(signer.getSID());

			for (X509CertificateHolder x509CertificateHolder : certCollection) {

				SignerInformationVerifier singInfoVer = verifier
						.build(x509CertificateHolder);
 
				X509Certificate x509Certificate = jcaX509CertificateConverter
						.getCertificate(x509CertificateHolder);

				x509Certificate.checkValidity();

				if (!signer.verify(singInfoVer)) {
					throw new Exception("signature invalid");
				}
				certificates.add(x509Certificate);
			}
		}
	}

	public PECVerifier() {
		this.bcprov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
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

 

	public PECMessageInfos verifyAnalizePEC(final InputStream imailstream, long uid, String account) {

		final Properties props = System.getProperties();
		final Session session = Session.getDefaultInstance(props, null);
		Document datiCert = null;
		PECMail pecMail = null;
		Boolean esito = false;
		List<CertificateInfo> certificateInfo = null;
		try {
			final MimeMessage msg = new MimeMessage(session, imailstream);

			if (msg.isMimeType("multipart/signed")
					|| msg.isMimeType("application/pkcs7-mime")) {

				final SMIMESignedParser s = new SMIMESignedParser(
						digestCalculatorProvider,
						(MimeMultipart) msg.getContent());

				datiCert = extractDatiCertXML(s);
				
				pecMail = extractPecMail(   msg , uid , account );
				
				certificateInfo = verifySignature(s);

				esito = true;

			} else {
				throw new Exception("NO Pec [" + msg.getContentType() + "]");
			}

			final PECMessageInfos docVer = new PECMessageInfos(certificateInfo,
					datiCert, pecMail, esito);
			return docVer;

		} catch (Exception e) {
			logger.error("pec verify mail", e);
			final PECMessageInfos docVer = new PECMessageInfos(certificateInfo,
					datiCert, pecMail, esito);
			docVer.setException(e);
			return docVer;
		}

	}

	private static final String dirBase="extractedpec"+File.separator;
	
	public static void bodyPecWithAttachment(InputStream imailstream,  PECMail mail) throws Exception {
		File attachmentDir = new File( dirBase + mail.getUid() +File.separator +PecConstant.POSTACERTDIR+ File.separator);
		attachmentDir.mkdirs();
		final Properties props = System.getProperties();
		final Session session = Session.getDefaultInstance(props, null);
		final MimeMessage msg = new MimeMessage(session, imailstream);
		
		MimeMessageParser parser = new MimeMessageParser(msg);
		parser.parse();
		mail.setHasAttachments(parser.hasAttachments());
		if (parser.hasAttachments()) {
			for (DataSource data : parser.getAttachmentList()) {
				File attachment = new File( attachmentDir.getAbsolutePath() +"/" + data.getName() );
				FileOutputStream output = new FileOutputStream(attachment);
				IOUtils.copy(data.getInputStream(), output);
				output.close();
				mail.getAttachments().add(attachment);
			}
		}

		if (parser.getHtmlContent() != null) {
			mail.setBodyType("html");
			mail.setBody(parser.getHtmlContent());
		} else {
			mail.setBodyType("text");
			mail.setBody(parser.getPlainContent());
		}
	}
	
	private PECMail  extractPecMail(MimeMessage message, long uid, String account) throws Exception {
	
		final PECMail pecMail = new PECMail();
		String uidPecDir = account +File.separator + uid;
		pecMail.setUid( uidPecDir);
		
		File attachmentDir = new File(dirBase + uidPecDir   );
		attachmentDir.mkdirs();
		MimeMessageParser parser = new MimeMessageParser(message);
		parser.parse();
		if (parser.hasAttachments()) {
			
			for (DataSource data : parser.getAttachmentList()) {
				if(PecConstant.POSTACERT.equals( data.getName() ) ){
					File postacert = new File( attachmentDir.getAbsolutePath() +"/" + data.getName() );
					FileOutputStream output = new FileOutputStream(postacert);
					IOUtils.copy(data.getInputStream(), output);
					IOUtils.closeQuietly( output );
					
					FileInputStream imailstream = new FileInputStream( postacert );
					bodyPecWithAttachment(imailstream, pecMail);
					
					
				}
				
				
				
			}
		}
		
		
		
		
		return pecMail;
	}

	private Document extractDatiCertXML(final SMIMESignedParser s)
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
