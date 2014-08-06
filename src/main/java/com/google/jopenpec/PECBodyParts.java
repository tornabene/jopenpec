package com.google.jopenpec;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.activation.DataHandler;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;

public class PECBodyParts {

	private final List<DataHandler> attachments = new Vector<DataHandler>();

	private BodyPart bodyTextHTML = null;
	private BodyPart bodyTextPlain = null;
	private final HashMap<String, BodyPart> mapBodyPart = new HashMap<String, BodyPart>();

	public final List<DataHandler> getAttachments() {
		return this.attachments;
	}

	public BodyPart getBodyPart(final String keyContentType) {
		return this.mapBodyPart.get(keyContentType);
	}

	public final BodyPart getBodyTextHTML() {
		return this.bodyTextHTML;
	}

	public final BodyPart getBodyTextPlain() {
		return this.bodyTextPlain;
	}

	public int getCountBodyParts() {
		return this.mapBodyPart.size();
	}

	public DataHandler getDataHandlerByPartKey(final String keyContentType)
			throws MessagingException {
		final BodyPart bodyPiece = this.mapBodyPart.get(keyContentType);
		final DataHandler dataHandler = bodyPiece.getDataHandler();

		return dataHandler;
	}

	public Set<String> getKeysContentType() {
		return this.mapBodyPart.keySet();
	}

	public void putBodyPart(final BodyPart bodyPiece) throws MessagingException {
		this.mapBodyPart.put(bodyPiece.getContentType(), bodyPiece);

	}

	public void setBodyPartsMime() throws MessagingException, IOException {
		final List<DataHandler> listDataSource = new Vector<DataHandler>();
		final Set<String> listKeyContentType = getKeysContentType();
		final Iterator<String> iterKeyContentType = listKeyContentType
				.iterator();

		while (iterKeyContentType.hasNext()) {
			listDataSource.add(getDataHandlerByPartKey(iterKeyContentType
					.next()));
		}
		this.attachments.clear();
		for (int i = 0; i < listDataSource.size(); i++) {
			final DataHandler dataHandler = listDataSource.get(i);
			if (dataHandler.getContentType().matches(".*multipart.*")) {
				final MimeMultipart multiPart = (MimeMultipart) dataHandler
						.getContent();
				BodyPart bodyPieceMime;
				for (int j = 0; j < multiPart.getCount(); j++) {
					bodyPieceMime = multiPart.getBodyPart(j);
					if (bodyPieceMime.getContentType()
							.matches(".*text/plain.*")) {
						this.bodyTextPlain = bodyPieceMime;
					} else if (bodyPieceMime.getContentType().matches(
							".*text/html.*")) {
						this.bodyTextHTML = bodyPieceMime;
					}
				}
			} else {
				final String name = getAttachmentName(dataHandler);
				if ((name != null) && !name.equals("daticert.xml")) {
					this.attachments.add(dataHandler);
				}
			}
		}

	}

	private String getAttachmentName(final DataHandler dataHandler) {
		String name = dataHandler.getContentType();
		final String[] splitOne = name.split(";");
		final String[] splitTwo = splitOne[1].split("=");
		name = splitTwo[1];
		return name;
	}

}
