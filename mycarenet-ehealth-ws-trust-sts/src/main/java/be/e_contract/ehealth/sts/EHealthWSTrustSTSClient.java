/*
 * Java MyCareNet Project.
 * Copyright (C) 2023-2024 e-Contract.be BV.
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
package be.e_contract.ehealth.sts;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBElement;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Holder;
import javax.xml.ws.handler.Handler;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import be.e_contract.ehealth.sts.ws.jaxb.authz.ClaimType;
import be.e_contract.ehealth.sts.ws.jaxb.wsse.SecurityTokenReferenceType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.ClaimsType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.LifetimeType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.ObjectFactory;
import be.e_contract.ehealth.sts.ws.jaxb.wst.RequestSecurityTokenResponseType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.RequestSecurityTokenType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.SignChallengeType;
import be.e_contract.ehealth.sts.ws.jaxb.wst.UseKeyType;
import be.e_contract.ehealth.sts.ws.jaxb.wsu.AttributedDateTime;
import be.e_contract.ehealth.sts.ws.jaxb.xmldsig.X509DataType;
import be.e_contract.ehealth.sts.ws.jaxws.SecurityTokenService;
import be.e_contract.ehealth.sts.ws.jaxws.SecurityTokenServicePort;
import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.ehealth.common.TracingClient;
import be.e_contract.mycarenet.ehealth.common.TracingSOAPHandler;
import be.e_contract.mycarenet.ehealth.common.X509CredentialClient;

public class EHealthWSTrustSTSClient implements TracingClient, X509CredentialClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(EHealthWSTrustSTSClient.class);

	private PrivateKey privateKey;
	private X509Certificate certificate;

	private PrivateKey challengePrivateKey;
	private X509Certificate challengeCertificate;

	private final SecurityTokenServicePort port;

	private final WSSecuritySOAPHandler wsSecuritySOAPHandler;

	private final TracingSOAPHandler tracingSOAPHandler;

	private final InboundAssertionSOAPHandler inboundAssertionSOAPHandler;

	private final ObjectFactory wsTrustObjectFactory;

	private final be.e_contract.ehealth.sts.ws.jaxb.wsu.ObjectFactory wsuObjectFactory;

	private final be.e_contract.ehealth.sts.ws.jaxb.wsse.ObjectFactory wsseObjectFactory;

	private final be.e_contract.ehealth.sts.ws.jaxb.xmldsig.ObjectFactory dsObjectFactory;

	private final be.e_contract.ehealth.sts.ws.jaxb.authz.ObjectFactory authzObjectFactory;

	public EHealthWSTrustSTSClient(String location) {
		SecurityTokenService securityTokenService = SecurityTokenServiceFactory.newInstance();
		this.port = securityTokenService.getSecurityTokenServicePort();

		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();

		List<Handler> handlerChain = binding.getHandlerChain();
		this.wsSecuritySOAPHandler = new WSSecuritySOAPHandler();
		this.tracingSOAPHandler = new TracingSOAPHandler();
		handlerChain.add(this.wsSecuritySOAPHandler);
		handlerChain.add(this.tracingSOAPHandler);
		handlerChain.add(new LoggingHandler());
		this.inboundAssertionSOAPHandler = new InboundAssertionSOAPHandler();
		handlerChain.add(this.inboundAssertionSOAPHandler);
		binding.setHandlerChain(handlerChain);

		this.wsTrustObjectFactory = new ObjectFactory();
		this.wsuObjectFactory = new be.e_contract.ehealth.sts.ws.jaxb.wsu.ObjectFactory();
		this.wsseObjectFactory = new be.e_contract.ehealth.sts.ws.jaxb.wsse.ObjectFactory();
		this.dsObjectFactory = new be.e_contract.ehealth.sts.ws.jaxb.xmldsig.ObjectFactory();
		this.authzObjectFactory = new be.e_contract.ehealth.sts.ws.jaxb.authz.ObjectFactory();
	}

	@Override
	public void setTracing(String userAgent, String from) {
		this.tracingSOAPHandler.setTracing(userAgent, from);
	}

	public Element issueAssertion(X509Certificate certificate, List<Claim> claims) throws CertificateEncodingException {
		RequestSecurityTokenType requestSecurityToken = this.wsTrustObjectFactory.createRequestSecurityTokenType();
		String context = "context-" + UUID.randomUUID().toString();
		requestSecurityToken.setContext(context);
		requestSecurityToken.getAny().add(this.wsTrustObjectFactory
				.createTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"));
		requestSecurityToken.getAny().add(
				this.wsTrustObjectFactory.createRequestType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"));

		ClaimsType jaxbClaims = this.wsTrustObjectFactory.createClaimsType();
		jaxbClaims.setDialect("http://docs.oasis-open.org/wsfed/authorization/200706/authclaims");
		requestSecurityToken.getAny().add(this.wsTrustObjectFactory.createClaims(jaxbClaims));
		for (Claim claim : claims) {
			ClaimType jaxbClaim = this.authzObjectFactory.createClaimType();
			jaxbClaim.setUri(claim.getName());
			jaxbClaim.setValue(claim.getValue());
			jaxbClaims.getAny().add(this.authzObjectFactory.createClaimType(jaxbClaim));
		}

		LifetimeType lifetime = this.wsTrustObjectFactory.createLifetimeType();
		requestSecurityToken.getAny().add(this.wsTrustObjectFactory.createLifetime(lifetime));
		AttributedDateTime created = this.wsuObjectFactory.createAttributedDateTime();
		LocalDateTime createdDateTime = LocalDateTime.now();
		DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssZ");
		created.setValue(createdDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("UTC"))
				.format(dateTimeFormatter));
		lifetime.setCreated(created);

		AttributedDateTime expires = this.wsuObjectFactory.createAttributedDateTime();
		LocalDateTime expiresDateTime = createdDateTime.plusHours(24);
		expires.setValue(expiresDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("UTC"))
				.format(dateTimeFormatter));
		lifetime.setExpires(expires);

		requestSecurityToken.getAny().add(
				this.wsTrustObjectFactory.createKeyType("http://docs.oasis-open.org/ws-sx/wstrust/200512/PublicKey"));

		UseKeyType useKey = this.wsTrustObjectFactory.createUseKeyType();
		requestSecurityToken.getAny().add(this.wsTrustObjectFactory.createUseKey(useKey));
		SecurityTokenReferenceType securityTokenReference = this.wsseObjectFactory.createSecurityTokenReferenceType();
		useKey.setAny(this.wsseObjectFactory.createSecurityTokenReference(securityTokenReference));

		X509DataType x509Data = this.dsObjectFactory.createX509DataType();
		securityTokenReference.getAny().add(this.dsObjectFactory.createX509Data(x509Data));
		x509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName()
				.add(this.dsObjectFactory.createX509DataTypeX509Certificate(certificate.getEncoded()));

		RequestSecurityTokenResponseType requestSecurityTokenResponse = this.port.issue(requestSecurityToken);

		Element assertion = this.inboundAssertionSOAPHandler.getAssertion();
		if (null != assertion) {
			return assertion;
		}

		for (Object responseObject : requestSecurityTokenResponse.getAny()) {
			if (responseObject instanceof JAXBElement) {
				JAXBElement responseElement = (JAXBElement) responseObject;
				LOGGER.debug("response element name: {}", responseElement.getName());
				LOGGER.debug("response element value: {}", responseElement.getValue());
				Object responseValue = responseElement.getValue();
				if (responseValue instanceof SignChallengeType) {
					SignChallengeType signChallenge = (SignChallengeType) responseValue;
					SignChallengeType signChallengeResponse = this.wsTrustObjectFactory.createSignChallengeType();
					signChallengeResponse.setChallenge(signChallenge.getChallenge());
					requestSecurityTokenResponse = this.wsTrustObjectFactory.createRequestSecurityTokenResponseType();
					requestSecurityTokenResponse.getAny()
							.add(this.wsTrustObjectFactory.createSignChallengeResponse(signChallengeResponse));
					Holder<RequestSecurityTokenResponseType> request = new Holder<>(requestSecurityTokenResponse);
					this.wsSecuritySOAPHandler.setCredential(this.challengePrivateKey, this.challengeCertificate);
					try {
						LOGGER.debug("STS challenge");
						this.port.challenge(request);
					} finally {
						// restore default credential
						this.wsSecuritySOAPHandler.setCredential(this.privateKey, this.certificate);
					}
				}
			}
		}

		assertion = this.inboundAssertionSOAPHandler.getAssertion();
		return assertion;
	}

	@Override
	public void setCredentials(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
		this.wsSecuritySOAPHandler.setCredential(privateKey, certificate);
	}

	public void setChallengeCredentials(PrivateKey privateKey, X509Certificate certificate) {
		this.challengePrivateKey = privateKey;
		this.challengeCertificate = certificate;
	}

	public String toString(Element element) {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new RuntimeException(e);
		}
		StringWriter stringWriter = new StringWriter();
		try {
			transformer.transform(new DOMSource(element), new StreamResult(stringWriter));
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		return stringWriter.toString();
	}

	/**
	 * Returns the value of the NotOnOrAfter element within the given SAML
	 * assertion.
	 *
	 * @param assertionElement
	 * @return
	 */
	public DateTime getNotAfter(Element assertionElement) {
		NodeList conditionsNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion",
				"Conditions");
		Element conditionsElement = (Element) conditionsNodeList.item(0);
		String notOnOrAfterAttributeValue = conditionsElement.getAttribute("NotOnOrAfter");
		Calendar calendar = DatatypeConverter.parseDateTime(notOnOrAfterAttributeValue);
		return new DateTime(calendar.getTime());
	}
}
