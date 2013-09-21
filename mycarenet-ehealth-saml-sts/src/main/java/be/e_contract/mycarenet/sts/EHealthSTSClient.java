/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 Frank Cornelis.
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

package be.e_contract.mycarenet.sts;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.jaxws.sts.EHealthSamlStsService;

public class EHealthSTSClient {

	public static final String NAME_IDENTIFIER_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

	public static final String CONFIRMATION_METHOD_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

	private static final Log LOG = LogFactory.getLog(EHealthSTSClient.class);

	private final Dispatch dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	public EHealthSTSClient(String location) throws Exception {
		EHealthSamlStsService service = EHealthSamlStsServiceFactory
				.newInstance();

		QName portQName = new QName("urn:be:ehealth:saml:sts:1.0",
				"EHealthSamlStsPort");
		this.dispatch = service.createDispatch(portQName, Source.class,
				Service.Mode.PAYLOAD);

		this.dispatch.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = dispatch.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	public void requestAssertion(X509Certificate authnCertificate,
			PrivateKey authnPrivateKey, X509Certificate hokCertificate,
			PrivateKey hokPrivateKey) throws Exception {
		this.wsSecuritySOAPHandler.setCertificate(authnCertificate);
		this.wsSecuritySOAPHandler.setPrivateKey(authnPrivateKey);

		RequestFactory requestFactory = new RequestFactory();
		Element requestElement = requestFactory.createRequest(authnCertificate,
				hokPrivateKey, hokCertificate);
		
		

		this.dispatch.invoke(new DOMSource(requestElement));
	}
}
