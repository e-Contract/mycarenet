/*
 * Java MyCareNet Project.
 * Copyright (C) 2012 Frank Cornelis.
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

package be.e_contract.mycarenet.xkms;

import java.util.List;
import java.util.UUID;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.jaxb.xkms.AssertionStatusType;
import be.e_contract.mycarenet.jaxb.xkms.AuthInfoType;
import be.e_contract.mycarenet.jaxb.xkms.AuthUserInfoType;
import be.e_contract.mycarenet.jaxb.xkms.KeyBindingType;
import be.e_contract.mycarenet.jaxb.xkms.ObjectFactory;
import be.e_contract.mycarenet.jaxb.xkms.ProofOfPossessionType;
import be.e_contract.mycarenet.jaxb.xkms.RegisterResultType;
import be.e_contract.mycarenet.jaxb.xkms.RegisterType;
import be.e_contract.mycarenet.jaxb.xkms.RespondEnum;
import be.e_contract.mycarenet.jaxb.xkms.RespondType;
import be.e_contract.mycarenet.jaxb.xkms.ResultCodeType;
import be.e_contract.mycarenet.jaxb.xmldsig.KeyInfoType;
import be.e_contract.mycarenet.jaxb.xmldsig.KeyValueType;
import be.e_contract.mycarenet.jaxb.xmldsig.RSAKeyValueType;
import be.e_contract.mycarenet.jaxws.xkms.KeyServicePortType;
import be.e_contract.mycarenet.jaxws.xkms.RegisterResult;
import be.e_contract.mycarenet.jaxws.xkms.XMLKeyManagementService;

/**
 * MyCareNet XKMS client. This client is interesting for revoking MyCareNet
 * session keys, as the XKMS version 1.0 protocol does not require an
 * authentication signature for revoking the session key.
 * 
 * @author Frank Cornelis
 * 
 */
public class XKMSClient {

	private static final Log LOG = LogFactory.getLog(XKMSClient.class);

	private final KeyServicePortType port;

	private final ObjectFactory objectFactory;

	private final be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory;

	private final ProofOfPossessionSignatureSOAPHandler proofOfPossessionSignatureSOAPHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the URL of the MyCareNet XKMS web service.
	 */
	public XKMSClient(String location) {
		XMLKeyManagementService service = XKMSServiceFactory.newInstance();
		this.port = service.getKeyServiceSoapPort();
		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		this.proofOfPossessionSignatureSOAPHandler = new ProofOfPossessionSignatureSOAPHandler();
		handlerChain.add(this.proofOfPossessionSignatureSOAPHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.xmldsigObjectFactory = new be.e_contract.mycarenet.jaxb.xmldsig.ObjectFactory();
	}

	/**
	 * Revoke the given session key.
	 * 
	 * @param sessionKey
	 */
	public void revokeSessionKey(SessionKey sessionKey) {
		RegisterType register = this.objectFactory.createRegisterType();

		String prototypeId = addPrototype(sessionKey, register);

		addRespond(register);

		addProofOfPossession(sessionKey, register, prototypeId);

		RegisterResultType registerResult;
		try {
			registerResult = this.port.register(register);
		} catch (RegisterResult e) {
			LOG.error("revocation error: " + e.getMessage(), e);
			return;
		}
		if (ResultCodeType.SUCCESS == registerResult.getResult()) {
			sessionKey.setValidity(null, null);
		}
	}

	private String addPrototype(SessionKey sessionKey, RegisterType register) {
		KeyBindingType prototype = this.objectFactory.createKeyBindingType();
		register.setPrototype(prototype);

		String prototypeId = "prototype-" + UUID.randomUUID().toString();
		prototype.setId(prototypeId);

		prototype.setStatus(AssertionStatusType.INVALID);

		KeyInfoType keyInfo = this.xmldsigObjectFactory.createKeyInfoType();
		prototype.setKeyInfo(keyInfo);

		KeyValueType keyValue = this.xmldsigObjectFactory.createKeyValueType();
		keyInfo.getContent().add(
				this.xmldsigObjectFactory.createKeyValue(keyValue));

		RSAKeyValueType rsaKeyValue = this.xmldsigObjectFactory
				.createRSAKeyValueType();
		keyValue.getContent().add(
				this.xmldsigObjectFactory.createRSAKeyValue(rsaKeyValue));

		rsaKeyValue.setModulus(sessionKey.getModulus());
		rsaKeyValue.setExponent(sessionKey.getExponent());

		return prototypeId;
	}

	private void addRespond(RegisterType register) {
		RespondType respond = this.objectFactory.createRespondType();
		respond.getString().add(RespondEnum.STATUS);
		register.setRespond(respond);
	}

	private void addProofOfPossession(SessionKey sessionKey,
			RegisterType register, String prototypeId) {
		AuthInfoType authInfo = this.objectFactory.createAuthInfoType();
		register.setAuthInfo(authInfo);
		AuthUserInfoType authUserInfo = this.objectFactory
				.createAuthUserInfoType();
		authInfo.setAuthUserInfo(authUserInfo);
		ProofOfPossessionType proofOfPossession = this.objectFactory
				.createProofOfPossessionType();
		authUserInfo.setProofOfPossession(proofOfPossession);
		this.proofOfPossessionSignatureSOAPHandler.setSessionKey(sessionKey);
		this.proofOfPossessionSignatureSOAPHandler.setPrototypeId(prototypeId);
	}
}
