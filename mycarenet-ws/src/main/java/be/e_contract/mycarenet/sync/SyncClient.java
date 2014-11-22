/*
 * Java MyCareNet Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.sync;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.namespace.QName;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.async.PackageLicenseKey;
import be.e_contract.mycarenet.async.SecurityDecorator;
import be.e_contract.mycarenet.common.PayloadLogicalHandler;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.jaxb.sync.XmlDocumentWrapperType;
import be.e_contract.mycarenet.jaxws.sync.CareProviderSyncPortType;
import be.e_contract.mycarenet.jaxws.sync.FaultMessage;
import be.e_contract.mycarenet.jaxws.sync.MyCarenetCareProviderSyncService;

/**
 * MyCareNet Synchronous web service client.
 * 
 * @author Frank Cornelis
 * 
 */
public class SyncClient {

	private final CareProviderSyncPortType syncPort;

	private final PayloadLogicalHandler payloadLogicalHandler;

	private final Dispatch<Source> dispatch;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the URL of the MyCareNet synchronous web service.
	 * @param sessionKey
	 *            the registered MyCareNet session key.
	 * @param packageLicenseKey
	 *            the MyCareNet package license key.
	 */
	public SyncClient(String location, SessionKey sessionKey,
			PackageLicenseKey packageLicenseKey) {
		MyCarenetCareProviderSyncService service = MyCareNetSyncServiceFactory
				.newInstance();
		this.syncPort = service.getCareProviderSyncPort();
		SecurityDecorator securityDecorator = new SecurityDecorator(sessionKey,
				packageLicenseKey, location);
		this.payloadLogicalHandler = securityDecorator
				.decorate((BindingProvider) this.syncPort);

		QName portQName = new QName("urn:be:cin:mycarenet:1.0:sync",
				"CareProviderSyncPort");
		this.dispatch = service.createDispatch(portQName, Source.class,
				Service.Mode.PAYLOAD);
		securityDecorator.decorate((BindingProvider) this.dispatch);
	}

	public XmlDocumentWrapperType echo(XmlDocumentWrapperType message)
			throws FaultMessage {
		return this.syncPort.echo(message);
	}

	/**
	 * Returns the SOAP payload as a string.
	 * 
	 * @return
	 */
	public String getPayload() {
		return this.payloadLogicalHandler.getPayload();
	}

	/**
	 * Invokes a method on the MyCareNet sync web service using the low-level
	 * SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public Element invoke(Element request) {
		Source responseSource = this.dispatch.invoke(new DOMSource(request));
		Element responseElement = toElement(responseSource);
		return responseElement;
	}

	/**
	 * Invokes a method on the MyCareNet sync web service using the low-level
	 * SOAP payload.
	 * 
	 * @param request
	 * @return
	 */
	public String invoke(String request) {
		Source responseSource = this.dispatch.invoke(new StreamSource(
				new StringReader(request)));
		return toString(responseSource);
	}

	private String toString(Source source) {
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		try {
			transformer.transform(source, result);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		return stringWriter.toString();
	}

	private Element toElement(Source source) {
		if (source instanceof DOMSource) {
			DOMSource domSource = (DOMSource) source;
			return (Element) domSource.getNode();
		}
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		DOMResult domResult = new DOMResult();
		try {
			transformer.transform(source, domResult);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		Document document = (Document) domResult.getNode();
		return (Element) document.getDocumentElement();
	}
}
