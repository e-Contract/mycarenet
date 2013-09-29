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
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.w3c.dom.Element;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.jaxws.sts.EHealthSamlStsService;

public class EHealthSTSClient {

	public static final String NAME_IDENTIFIER_X509_SUBJECT_NAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";

	public static final String CONFIRMATION_METHOD_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

	private static final Log LOG = LogFactory.getLog(EHealthSTSClient.class);

	private final Dispatch<Source> dispatch;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	public EHealthSTSClient(String location) {
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

	public Assertion requestAssertion(X509Certificate authnCertificate,
			PrivateKey authnPrivateKey, X509Certificate hokCertificate,
			PrivateKey hokPrivateKey) throws Exception {
		this.wsSecuritySOAPHandler.setCertificate(authnCertificate);
		this.wsSecuritySOAPHandler.setPrivateKey(authnPrivateKey);

		RequestFactory requestFactory = new RequestFactory();
		Request request = requestFactory.createRequest(authnCertificate,
				hokPrivateKey, hokCertificate);
		Element requestElement = request.getDOM();

		Source responseSource = this.dispatch.invoke(new DOMSource(
				requestElement));

		DOMSource responseDOMSource = (DOMSource) responseSource;
		Element responseElement = (Element) responseDOMSource.getNode();
		UnmarshallerFactory unmarshallerFactory = Configuration
				.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory
				.getUnmarshaller(responseElement);
		XMLObject xmlObject = unmarshaller.unmarshall(responseElement);
		Response response = (Response) xmlObject;
		
		if (false == request.getID().equals(response.getInResponseTo())) {
			throw new IllegalStateException("incorrect InResponseTo");
		}
		
		Status status = response.getStatus();
		StatusCode statusCode = status.getStatusCode();
		if (false == StatusCode.SUCCESS.equals(statusCode.getValue())) {
			throw new IllegalStateException("SAMLP status code incorrect");
		}
		
		List<Assertion> assertions = response.getAssertions();
		Assertion assertion = assertions.get(0);
		return assertion;
	}
}
