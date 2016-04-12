/*
 * Java MyCareNet Project.
 * Copyright (C) 2016 e-Contract.be BVBA.
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

package be.e_contract.mycarenet.certra;

import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;

import be.e_contract.mycarenet.certra.cms.CMSSigner;
import be.e_contract.mycarenet.certra.cms.revoke.ObjectFactory;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataRequest;
import be.e_contract.mycarenet.certra.jaxb.protocol.GetRevocableCertificatesRequest;
import be.e_contract.mycarenet.certra.jaxws.CertRaPortType;
import be.e_contract.mycarenet.certra.jaxws.CertRaService;
import be.e_contract.mycarenet.common.LoggingHandler;

public class CertRAClient {

	private final CertRaPortType port;

	public CertRAClient(String location) {
		CertRaService certRaService = CertRaServiceFactory.newInstance();
		this.port = certRaService.getCertRaPort();

		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		// LoggingHandler makes CXF fail on the attachments.
		// https://issues.apache.org/jira/browse/CXF-5496
		binding.setHandlerChain(handlerChain);
	}

	public void getRevocableCertificates(PrivateKey nonRepPrivateKey, X509Certificate nonRepCertificate)
			throws SignatureException {
		String ssin = getSSIN(nonRepCertificate);

		ObjectFactory dataObjectFactory = new ObjectFactory();
		RevocableCertificatesDataRequest requestData = dataObjectFactory.createRevocableCertificatesDataRequest();
		requestData.setSSIN(ssin);

		CMSSigner cmsSigner = new CMSSigner(nonRepPrivateKey, nonRepCertificate);
		byte[] data = cmsSigner.sign(requestData);

		be.e_contract.mycarenet.certra.jaxb.protocol.ObjectFactory objectFactory = new be.e_contract.mycarenet.certra.jaxb.protocol.ObjectFactory();
		GetRevocableCertificatesRequest request = objectFactory.createGetRevocableCertificatesRequest();
		request.setRevocableCertificatesDataRequest(data);
		this.port.getRevocableCertificates(request);
	}

	private String getSSIN(X509Certificate certificate) {
		X500Principal userPrincipal = certificate.getSubjectX500Principal();
		String name = userPrincipal.toString();
		int serialNumberBeginIdx = name.indexOf("SERIALNUMBER=");
		if (-1 == serialNumberBeginIdx) {
			throw new SecurityException("SERIALNUMBER not found in X509 CN");
		}
		int serialNumberValueBeginIdx = serialNumberBeginIdx + "SERIALNUMBER=".length();
		int serialNumberValueEndIdx = name.indexOf(",", serialNumberValueBeginIdx);
		if (-1 == serialNumberValueEndIdx) {
			serialNumberValueEndIdx = name.length();
		}
		String userId = name.substring(serialNumberValueBeginIdx, serialNumberValueEndIdx);
		return userId;
	}
}
