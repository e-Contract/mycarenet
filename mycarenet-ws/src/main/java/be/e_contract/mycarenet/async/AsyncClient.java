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

package be.e_contract.mycarenet.async;

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import be.e_contract.mycarenet.common.LoggingHandler;
import be.e_contract.mycarenet.common.PayloadLogicalHandler;
import be.e_contract.mycarenet.common.SessionKey;
import be.e_contract.mycarenet.jaxb.async.DownloadRequestType;
import be.e_contract.mycarenet.jaxb.async.DownloadResultType;
import be.e_contract.mycarenet.jaxb.async.GetStatusRequestType;
import be.e_contract.mycarenet.jaxb.async.GetStatusResultType;
import be.e_contract.mycarenet.jaxb.async.PostFileRequestType;
import be.e_contract.mycarenet.jaxb.async.PostFileResultType;
import be.e_contract.mycarenet.jaxb.async.QueryDownloadableRequestType;
import be.e_contract.mycarenet.jaxb.async.QueryDownloadableResultType;
import be.e_contract.mycarenet.jaxws.async.CareProviderAsyncPortType;
import be.e_contract.mycarenet.jaxws.async.FaultMessage;
import be.e_contract.mycarenet.jaxws.async.MyCarenetCareProviderAsyncService;

/**
 * MyCareNet Asynchronous web service client.
 * 
 * @author Frank Cornelis
 * 
 */
public class AsyncClient {

	private final CareProviderAsyncPortType asyncPort;

	private final PayloadLogicalHandler payloadLogicalHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the URL of the MyCareNet asynchronous web service.
	 * @param sessionKey
	 *            the registered MyCareNet session key.
	 * @param packageLicenseKey
	 *            the MyCareNet package license key.
	 */
	public AsyncClient(String location, SessionKey sessionKey,
			PackageLicenseKey packageLicenseKey) {
		MyCarenetCareProviderAsyncService service = MyCareNetAsyncServiceFactory
				.newInstance();
		this.asyncPort = service.getCareProviderAsyncPort();
		BindingProvider bindingProvider = (BindingProvider) this.asyncPort;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		SecuritySOAPHandler sessionKeySignatureSOAPHandler = new SecuritySOAPHandler(
				sessionKey, packageLicenseKey);
		handlerChain.add(sessionKeySignatureSOAPHandler);
		handlerChain.add(new LoggingHandler());
		this.payloadLogicalHandler = new PayloadLogicalHandler();
		handlerChain.add(this.payloadLogicalHandler);
		binding.setHandlerChain(handlerChain);
	}

	public String echo(String message) {
		try {
			return this.asyncPort.echo(message);
		} catch (FaultMessage e) {
			throw new RuntimeException("echo error: " + e.getMessage(), e);
		}
	}

	public PostFileResultType postFile(PostFileRequestType postFileRequest)
			throws FaultMessage {
		return this.asyncPort.postFile(postFileRequest);
	}

	public QueryDownloadableResultType queryDownloadable(
			QueryDownloadableRequestType queryDownloadableRequest)
			throws FaultMessage {
		return this.asyncPort.queryDownloadable(queryDownloadableRequest);
	}

	public GetStatusResultType getStatus(GetStatusRequestType getStatusRequest)
			throws FaultMessage {
		return this.asyncPort.getStatus(getStatusRequest);
	}

	public DownloadResultType download(DownloadRequestType downloadRequest)
			throws FaultMessage {
		return this.asyncPort.download(downloadRequest);
	}

	/**
	 * Returns the SOAP payload as a string.
	 * 
	 * @return
	 */
	public String getPayload() {
		return this.payloadLogicalHandler.getPayload();
	}
}
