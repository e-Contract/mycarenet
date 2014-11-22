/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.e_contract.mycarenet.ehbox;

import java.util.Map;

import javax.activation.DataHandler;
import javax.xml.bind.attachment.AttachmentUnmarshaller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A JAXB attachment unmarshaller. Can be used to inject SOAP attachments when
 * unmarshalling via JAXB.
 * 
 * @author Frank Cornelis
 * 
 */
public class SOAPAttachmentUnmarshaller extends AttachmentUnmarshaller {

	private static final Log LOG = LogFactory
			.getLog(SOAPAttachmentUnmarshaller.class);

	private final Map<String, DataHandler> messageAttachments;

	public SOAPAttachmentUnmarshaller(
			Map<String, DataHandler> messageAttachments) {
		this.messageAttachments = messageAttachments;
	}

	@Override
	public DataHandler getAttachmentAsDataHandler(String cid) {
		LOG.debug("getAttachmentAsDataHandler: " + cid);
		String identifier = cid.substring(4); // remove 'cid:'
		DataHandler dataHandler = this.messageAttachments.get(identifier);
		LOG.debug("has data handler: " + (null != dataHandler));
		return dataHandler;
	}

	@Override
	public byte[] getAttachmentAsByteArray(String cid) {
		LOG.debug("getAttachmenAsByteArray: " + cid);
		return null;
	}
}