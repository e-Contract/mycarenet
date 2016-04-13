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

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import be.e_contract.mycarenet.certra.cms.CMSSigner;
import be.e_contract.mycarenet.certra.cms.aqdr.EHActorQualitiesDataRequest;
import be.e_contract.mycarenet.certra.cms.aqdr.EHActorQualitiesDataResponse;
import be.e_contract.mycarenet.certra.cms.aqdr.EntityType;
import be.e_contract.mycarenet.certra.cms.revoke.ObjectFactory;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataRequest;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataResponse;
import be.e_contract.mycarenet.certra.jaxb.etee.core.OrganizationTypes;
import be.e_contract.mycarenet.certra.jaxb.protocol.GetEHActorQualitiesRequest;
import be.e_contract.mycarenet.certra.jaxb.protocol.GetEHActorQualitiesResponse;
import be.e_contract.mycarenet.certra.jaxb.protocol.GetRevocableCertificatesRequest;
import be.e_contract.mycarenet.certra.jaxb.protocol.GetRevocableCertificatesResponse;
import be.e_contract.mycarenet.certra.jaxb.protocol.OrganizationTypeResponse;
import be.e_contract.mycarenet.certra.jaxws.CertRaPortType;
import be.e_contract.mycarenet.certra.jaxws.CertRaService;
import be.e_contract.mycarenet.common.LoggingHandler;

public class CertRAClient {

	private static final Log LOG = LogFactory.getLog(CertRAClient.class);

	private final CertRaPortType port;

	private final be.e_contract.mycarenet.certra.jaxb.protocol.ObjectFactory protocolObjectFactory;

	public CertRAClient(String location) {
		CertRaService certRaService = CertRaServiceFactory.newInstance();
		this.port = certRaService.getCertRaPort();

		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		// LoggingHandler makes CXF fail on the attachments.
		// https://issues.apache.org/jira/browse/CXF-5496
		binding.setHandlerChain(handlerChain);

		this.protocolObjectFactory = new be.e_contract.mycarenet.certra.jaxb.protocol.ObjectFactory();
	}

	public RevocableCertificatesDataResponse getRevocableCertificates(PrivateKey nonRepPrivateKey,
			List<X509Certificate> nonRepCertificateChain) throws Exception {
		String ssin = getSSIN(nonRepCertificateChain.get(0));

		ObjectFactory dataObjectFactory = new ObjectFactory();
		RevocableCertificatesDataRequest requestData = dataObjectFactory.createRevocableCertificatesDataRequest();
		requestData.setSSIN(ssin);

		CMSSigner cmsSigner = new CMSSigner(nonRepPrivateKey, nonRepCertificateChain);
		byte[] requestCmsData = cmsSigner.sign(requestData);
		return getRevocableCertificates(requestCmsData);
	}

	public RevocableCertificatesDataResponse getRevocableCertificates(byte[] signedCms) throws Exception {

		GetRevocableCertificatesRequest request = this.protocolObjectFactory.createGetRevocableCertificatesRequest();
		request.setRevocableCertificatesDataRequest(signedCms);
		GetRevocableCertificatesResponse getRevocableCertificatesResponse = this.port.getRevocableCertificates(request);

		byte[] responseCmsData = getRevocableCertificatesResponse.getRevocableCertificatesDataResponse();

		byte[] responseData = getCmsData(responseCmsData);

		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		RevocableCertificatesDataResponse revocableCertificatesDataResponse = (RevocableCertificatesDataResponse) unmarshaller
				.unmarshal(new ByteArrayInputStream(responseData));
		return revocableCertificatesDataResponse;
	}

	private byte[] getCmsData(byte[] cms) throws Exception {
		CMSSignedData cmsSignedData = new CMSSignedData(cms);
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = (SignerInformation) signers.getSigners().iterator().next();
		SignerId signerId = signer.getSID();

		Store certificateStore = cmsSignedData.getCertificates();
		Collection<X509CertificateHolder> certificateCollection = certificateStore.getMatches(signerId);

		X509CertificateHolder certificateHolder = certificateCollection.iterator().next();
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));
		// we trust SSL here, no need for explicit verification of CMS signing
		// certificate

		LOG.debug("CMS signing certificate subject: " + certificate.getSubjectX500Principal());

		SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
				.build(certificate);
		boolean signatureResult = signer.verify(signerInformationVerifier);
		if (false == signatureResult) {
			throw new SecurityException("woops");
		}

		CMSTypedData signedContent = cmsSignedData.getSignedContent();
		byte[] responseData = (byte[]) signedContent.getContent();

		return responseData;
	}

	public EHActorQualitiesDataResponse getActorQualities(PrivateKey nonRepPrivateKey,
			List<X509Certificate> nonRepCertificateChain) throws Exception {
		be.e_contract.mycarenet.certra.cms.aqdr.ObjectFactory aqdrObjectFactory = new be.e_contract.mycarenet.certra.cms.aqdr.ObjectFactory();
		EHActorQualitiesDataRequest dataRequest = aqdrObjectFactory.createEHActorQualitiesDataRequest();
		String ssin = getSSIN(nonRepCertificateChain.get(0));
		dataRequest.setSSIN(ssin);
		dataRequest.setEntityType(EntityType.NATURAL);

		CMSSigner cmsSigner = new CMSSigner(nonRepPrivateKey, nonRepCertificateChain);
		byte[] requestCmsData = cmsSigner.sign(dataRequest);
		return getActorQualities(requestCmsData);
	}

	public EHActorQualitiesDataResponse getActorQualities(byte[] signedCms) throws Exception {
		GetEHActorQualitiesRequest request = this.protocolObjectFactory.createGetEHActorQualitiesRequest();
		request.setEHActorQualitiesDataRequest(signedCms);

		GetEHActorQualitiesResponse response = this.port.getActorQualities(request);
		byte[] responseCms = response.getEHActorQualitiesDataResponse();

		byte[] responseData = getCmsData(responseCms);

		JAXBContext jaxbContext = JAXBContext.newInstance(be.e_contract.mycarenet.certra.cms.aqdr.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		EHActorQualitiesDataResponse ehActorQualitiesDataResponse = (EHActorQualitiesDataResponse) unmarshaller
				.unmarshal(new ByteArrayInputStream(responseData));
		return ehActorQualitiesDataResponse;
	}

	public List<OrganizationTypes> getOrganizationTypes() {
		OrganizationTypeResponse response = this.port.getGenericOrganizationTypes(null);
		return response.getOrganizationTypes();
	}

	public static String getSSIN(X509Certificate certificate) {
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
