/*
 * Java MyCareNet Project.
 * Copyright (C) 2012-2022 e-Contract.be BV.
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

package be.e_contract.mycarenet.xkms2;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.UUID;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.jaxb.xkms2.AuthenticationType;
import be.e_contract.mycarenet.jaxb.xkms2.KeyBindingAuthenticationType;
import be.e_contract.mycarenet.jaxb.xkms2.KeyBindingType;
import be.e_contract.mycarenet.jaxb.xkms2.ObjectFactory;
import be.e_contract.mycarenet.jaxb.xkms2.ProofOfPossessionType;
import be.e_contract.mycarenet.jaxb.xkms2.PrototypeKeyBindingType;
import be.e_contract.mycarenet.jaxb.xkms2.RegisterRequestType;
import be.e_contract.mycarenet.jaxb.xkms2.RegisterResultType;
import be.e_contract.mycarenet.jaxb.xkms2.RevokeRequestType;
import be.e_contract.mycarenet.jaxb.xkms2.RevokeResultType;
import be.e_contract.mycarenet.jaxb.xkms2.StatusType;
import be.e_contract.mycarenet.jaxb.xkms2.ValidityIntervalType;
import be.e_contract.mycarenet.jaxb.xmldsig.KeyInfoType;
import be.e_contract.mycarenet.jaxb.xmldsig.KeyValueType;
import be.e_contract.mycarenet.jaxb.xmldsig.RSAKeyValueType;
import be.e_contract.mycarenet.jaxws.xkms2.KeyServicePortType;
import be.e_contract.mycarenet.jaxws.xkms2.RegisterResult;
import be.e_contract.mycarenet.jaxws.xkms2.RevokeResult;
import be.e_contract.mycarenet.jaxws.xkms2.XMLKeyManagementService;

/**
 * Client for MyCareNet XKMS version 2.0 web service. A major disadvantage of
 * the XKMS 2.0 protocol is that it also requires an authentication signature
 * for the revocation process. Hence revoking a session key is easier via the
 * XKMS 1.0 protocol.
 * 
 * @author Frank Cornelis
 * 
 */
public class XKMS2Client {

	private static final Logger LOGGER = LoggerFactory.getLogger(XKMS2Client.class);

	private static final String SIGNATURE_KEY_USAGE = "http://www.w3.org/2002/03/xkms#Signature";

	private static final String VALID_STATUS = "http://www.w3.org/2002/03/xkms#Valid";

	private static final String SUCCESS_MAJOR_RESULT = "http://www.w3.org/2002/03/xkms#Success";

	private final KeyServicePortType keyServicePort;

	private final ObjectFactory objectFactory;

	private final be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory;

	private final DatatypeFactory datatypeFactory;

	private final ProofOfPossessionSignatureSOAPHandler proofOfPossessionSignatureSOAPHandler;

	private final KeyBindingAuthenticationSignatureSOAPHandler keyBindingAuthenticationSignatureSOAPHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location the URL of the MyCareNet XKMS 2.0 web service.
	 */
	public XKMS2Client(String location) {
		XMLKeyManagementService service = XKMS2ServiceFactory.newInstance();
		this.keyServicePort = service.getKeyServiceSoapPort();
		BindingProvider bindingProvider = (BindingProvider) this.keyServicePort;
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List<Handler> handlerChain = binding.getHandlerChain();
		this.proofOfPossessionSignatureSOAPHandler = new ProofOfPossessionSignatureSOAPHandler();
		handlerChain.add(new LoggingHandler());
		handlerChain.add(this.proofOfPossessionSignatureSOAPHandler);
		this.keyBindingAuthenticationSignatureSOAPHandler = new KeyBindingAuthenticationSignatureSOAPHandler();
		handlerChain.add(this.keyBindingAuthenticationSignatureSOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.xmldsigObjectFactory = new be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory();
		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException("DatatypeFactory error: " + e.getMessage(), e);
		}

	}

	/**
	 * Register the given session key.
	 * 
	 * @param sessionKey       the session key to be registered.
	 * @param authnPrivateKey  the eID authentication private key.
	 * @param authnCertificate the eID authentication certificate.
	 */
	public void registerSessionKey(SessionKey sessionKey, PrivateKey authnPrivateKey,
			X509Certificate authnCertificate) {
		LOGGER.debug("register session key");
		RegisterRequestType request = this.objectFactory.createRegisterRequestType();

		String prototypeKeyBindingId = addPrototypeKeyBinding(request, sessionKey);

		addProofOfPossession(request, sessionKey, prototypeKeyBindingId);

		addAuthentication(request, prototypeKeyBindingId, authnPrivateKey, authnCertificate);

		RegisterResultType registerResult;
		try {
			registerResult = this.keyServicePort.register(request);
		} catch (RegisterResult e) {
			LOGGER.error("RegisterResult exception");
			return;
		}

		List<KeyBindingType> keyBindingList = registerResult.getKeyBinding();
		if (keyBindingList.isEmpty()) {
			LOGGER.error("missing KeyBinding");
			return;
		}
		KeyBindingType keyBinding = keyBindingList.get(0);
		StatusType status = keyBinding.getStatus();
		if (null == status) {
			LOGGER.error("missing KeyBinding/Status");
			return;
		}
		String statusValue = status.getStatusValue();
		if (false == VALID_STATUS.equals(statusValue)) {
			LOGGER.error("status not valid");
			return;
		}
		ValidityIntervalType validityInterval = keyBinding.getValidityInterval();
		if (null == validityInterval) {
			LOGGER.error("missing KeyBinding/ValidityInterval");
			return;
		}
		Date notBefore = validityInterval.getNotBefore().toGregorianCalendar().getTime();
		Date notAfter = validityInterval.getNotOnOrAfter().toGregorianCalendar().getTime();
		sessionKey.setValidity(notBefore, notAfter);
	}

	/**
	 * Revoke the given MyCareNet session key.
	 * 
	 * @param sessionKey       the session key to be revoked.
	 * @param authnPrivateKey  the eID authentication private key.
	 * @param authnCertificate the eID authentication certificate.
	 */
	public void revokeSessionKey(SessionKey sessionKey, PrivateKey authnPrivateKey, X509Certificate authnCertificate) {
		LOGGER.debug("revoke session key");
		RevokeRequestType revokeRequest = this.objectFactory.createRevokeRequestType();
		String revokeKeyBindingId = addRevokeKeyBinding(revokeRequest, sessionKey);
		addAuthentication(revokeRequest, revokeKeyBindingId, authnPrivateKey, authnCertificate);

		this.proofOfPossessionSignatureSOAPHandler.setPrototypeKeyBindingId(null);
		this.proofOfPossessionSignatureSOAPHandler.setSessionKey(null);

		RevokeResultType revokeResult;
		try {
			revokeResult = this.keyServicePort.revoke(revokeRequest);
		} catch (RevokeResult e) {
			LOGGER.error("revoke error: " + e.getMessage(), e);
			return;
		}
		String resultMajor = revokeResult.getResultMajor();
		if (SUCCESS_MAJOR_RESULT.equals(resultMajor)) {
			sessionKey.setValidity(null, null);
		}
	}

	private void addAuthentication(RevokeRequestType revokeRequest, String revokeKeyBindingId,
			PrivateKey authnPrivateKey, X509Certificate authnCertificate) {
		AuthenticationType authentication = this.objectFactory.createAuthenticationType();
		revokeRequest.setAuthentication(authentication);

		KeyBindingAuthenticationType keyBindingAuthentication = this.objectFactory.createKeyBindingAuthenticationType();
		authentication.setKeyBindingAuthentication(keyBindingAuthentication);
		this.keyBindingAuthenticationSignatureSOAPHandler.setSigner(authnPrivateKey, authnCertificate);
		this.keyBindingAuthenticationSignatureSOAPHandler.setRevokeKeyBindingId(revokeKeyBindingId);
	}

	private String addRevokeKeyBinding(RevokeRequestType revokeRequest, SessionKey sessionKey) {
		KeyBindingType revokeKeyBinding = this.objectFactory.createKeyBindingType();
		revokeRequest.setRevokeKeyBinding(revokeKeyBinding);

		String revokeKeyBindingId = "revoke-" + UUID.randomUUID().toString();
		revokeKeyBinding.setId(revokeKeyBindingId);

		KeyInfoType keyInfo = this.xmldsigObjectFactory.createKeyInfoType();
		revokeKeyBinding.setKeyInfo(keyInfo);

		KeyValueType keyValue = this.xmldsigObjectFactory.createKeyValueType();
		keyInfo.getContent().add(this.xmldsigObjectFactory.createKeyValue(keyValue));

		RSAKeyValueType rsaKeyValue = this.xmldsigObjectFactory.createRSAKeyValueType();
		keyValue.getContent().add(this.xmldsigObjectFactory.createRSAKeyValue(rsaKeyValue));

		rsaKeyValue.setModulus(sessionKey.getModulus());
		rsaKeyValue.setExponent(sessionKey.getExponent());

		return revokeKeyBindingId;
	}

	private void addAuthentication(RegisterRequestType request, String prototypeKeyBindingId,
			PrivateKey authnPrivateKey, X509Certificate authnCertificate) {
		AuthenticationType authentication = this.objectFactory.createAuthenticationType();
		request.setAuthentication(authentication);

		KeyBindingAuthenticationType keyBindingAuthentication = this.objectFactory.createKeyBindingAuthenticationType();
		authentication.setKeyBindingAuthentication(keyBindingAuthentication);
		this.keyBindingAuthenticationSignatureSOAPHandler.setSigner(authnPrivateKey, authnCertificate);
		this.keyBindingAuthenticationSignatureSOAPHandler.setPrototypeKeyBindingId(prototypeKeyBindingId);
	}

	private void addProofOfPossession(RegisterRequestType request, SessionKey sessionKey,
			String prototypeKeyBindingId) {
		ProofOfPossessionType proofOfPossession = this.objectFactory.createProofOfPossessionType();
		request.setProofOfPossession(proofOfPossession);
		this.proofOfPossessionSignatureSOAPHandler.setSessionKey(sessionKey);
		this.proofOfPossessionSignatureSOAPHandler.setPrototypeKeyBindingId(prototypeKeyBindingId);
	}

	private String addPrototypeKeyBinding(RegisterRequestType registerRequest, SessionKey sessionKey) {
		PrototypeKeyBindingType prototypeKeyBinding = this.objectFactory.createPrototypeKeyBindingType();
		registerRequest.setPrototypeKeyBinding(prototypeKeyBinding);

		String prototypeKeyBindingId = "keybinding-" + UUID.randomUUID().toString();
		prototypeKeyBinding.setId(prototypeKeyBindingId);

		KeyInfoType keyInfo = this.xmldsigObjectFactory.createKeyInfoType();
		prototypeKeyBinding.setKeyInfo(keyInfo);

		KeyValueType keyValue = this.xmldsigObjectFactory.createKeyValueType();
		keyInfo.getContent().add(this.xmldsigObjectFactory.createKeyValue(keyValue));

		RSAKeyValueType rsaKeyValue = this.xmldsigObjectFactory.createRSAKeyValueType();
		keyValue.getContent().add(this.xmldsigObjectFactory.createRSAKeyValue(rsaKeyValue));

		rsaKeyValue.setModulus(sessionKey.getModulus());
		rsaKeyValue.setExponent(sessionKey.getExponent());

		prototypeKeyBinding.getKeyUsage().add(SIGNATURE_KEY_USAGE);

		ValidityIntervalType validityInterval = this.objectFactory.createValidityIntervalType();
		prototypeKeyBinding.setValidityInterval(validityInterval);

		DateTime notBefore = new DateTime();
		validityInterval.setNotBefore(toXMLGregorianCalendar(notBefore));
		DateTime notAfter = notBefore.plusHours(12);
		validityInterval.setNotOnOrAfter(toXMLGregorianCalendar(notAfter));

		return prototypeKeyBindingId;
	}

	private XMLGregorianCalendar toXMLGregorianCalendar(DateTime dateTime) {
		GregorianCalendar gregorianCalendar = new GregorianCalendar();
		gregorianCalendar.setTime(dateTime.toDate());
		XMLGregorianCalendar xmlGregorianCalendar = this.datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
		return xmlGregorianCalendar;
	}
}
