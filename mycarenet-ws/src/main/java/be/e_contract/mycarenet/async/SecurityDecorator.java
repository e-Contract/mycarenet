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

package be.e_contract.mycarenet.async;

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.PayloadLogicalHandler;
import be.e_contract.mycarenet.common.SessionKey;

/**
 * Decorator for MyCareNet WS-Security profile.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurityDecorator {

	private final SessionKey sessionKey;

	private final PackageLicenseKey packageLicenseKey;

	private final String location;

	/**
	 * Main constructor.
	 * 
	 * @param sessionKey
	 *            the MyCareNet session key.
	 * @param packageLicenseKey
	 *            the MyCareNet package license key.
	 * @param location
	 *            the MyCareNet web service location URL.
	 */
	public SecurityDecorator(SessionKey sessionKey,
			PackageLicenseKey packageLicenseKey, String location) {
		this.sessionKey = sessionKey;
		this.packageLicenseKey = packageLicenseKey;
		this.location = location;
	}

	/**
	 * Decorates a given JAX-WS port with the required security handlers.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS port to decorate.
	 * @return the added payload logical JAX-WS handler.
	 */
	public PayloadLogicalHandler decorate(BindingProvider bindingProvider) {
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.location);

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("rawtypes")
		List<Handler> handlerChain = binding.getHandlerChain();
		SecuritySOAPHandler sessionKeySignatureSOAPHandler = new SecuritySOAPHandler(
				this.sessionKey, this.packageLicenseKey);
		handlerChain.add(sessionKeySignatureSOAPHandler);
		handlerChain.add(new LoggingHandler());
		PayloadLogicalHandler payloadLogicalHandler = new PayloadLogicalHandler();
		handlerChain.add(payloadLogicalHandler);
		binding.setHandlerChain(handlerChain);
		return payloadLogicalHandler;
	}
}
