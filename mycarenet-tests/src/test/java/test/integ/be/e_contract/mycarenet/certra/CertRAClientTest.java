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

package test.integ.be.e_contract.mycarenet.certra;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import be.e_contract.mycarenet.certra.CertRAClient;
import be.e_contract.mycarenet.certra.CertRASession;
import be.e_contract.mycarenet.certra.cms.aqdr.EHActorQualitiesDataResponse;
import be.e_contract.mycarenet.certra.cms.aqdr.NaturalPerson;
import be.e_contract.mycarenet.certra.cms.aqdr.NaturalPerson.Quality;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificateType;
import be.e_contract.mycarenet.certra.cms.revoke.RevocableCertificatesDataResponse;
import be.e_contract.mycarenet.certra.jaxb.etee.core.OrganizationTypes;
import be.fedict.commons.eid.jca.BeIDKeyStoreParameter;
import be.fedict.commons.eid.jca.BeIDProvider;

public class CertRAClientTest {

	private static final Log LOG = LogFactory.getLog(CertRAClientTest.class);

	private PrivateKey signPrivateKey;

	private List<X509Certificate> signCertificateChain;

	private CertRAClient client;

	@BeforeClass
	public static void beforeClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Security.addProvider(new BeIDProvider());
	}

	@Before
	public void setUp() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("BeID");
		BeIDKeyStoreParameter beIDKeyStoreParameter = new BeIDKeyStoreParameter();
		beIDKeyStoreParameter.addPPDUName("digipass 870");
		beIDKeyStoreParameter.addPPDUName("digipass 875");
		beIDKeyStoreParameter.addPPDUName("digipass 920");
		keyStore.load(beIDKeyStoreParameter);
		this.signPrivateKey = (PrivateKey) keyStore.getKey("Signature", null);
		Certificate[] signCertificates = keyStore.getCertificateChain("Signature");

		this.signCertificateChain = new LinkedList<>();
		for (Certificate signCertificate : signCertificates) {
			this.signCertificateChain.add((X509Certificate) signCertificate);
		}

		this.client = new CertRAClient("https://services-acpt.ehealth.fgov.be/CertRa/v1");
	}

	@Test
	public void testGetRevocableCertificates() throws Exception {
		RevocableCertificatesDataResponse revocableCertificatesDataResponse = this.client
				.getRevocableCertificates(this.signPrivateKey, this.signCertificateChain);

		List<RevocableCertificateType> revocableCertificates = revocableCertificatesDataResponse
				.getRevocablePersonalCertificate();
		for (RevocableCertificateType revocableCertificate : revocableCertificates) {
			LOG.debug("subject DN: " + revocableCertificate.getAuthDN());
			LOG.debug("certificate serial number: " + revocableCertificate.getAuthSerial());
		}
	}

	@Test
	public void testGetActorQualities() throws Exception {
		EHActorQualitiesDataResponse response = this.client.getActorQualities(this.signPrivateKey,
				this.signCertificateChain);

		NaturalPerson naturalPerson = response.getNaturalPerson();
		List<Quality> qualities = naturalPerson.getQuality();
		for (Quality quality : qualities) {
			LOG.debug("NIHII: " + quality.getNIHII());
			LOG.debug("quality: " + quality.getName());
		}
	}

	@Test
	public void testGetOrganizationTypes() throws Exception {
		List<OrganizationTypes> organizationTypesList = this.client.getOrganizationTypes();
		for (OrganizationTypes organizationTypes : organizationTypesList) {
			LOG.debug("organization type : " + organizationTypes.getIdentifierType());
		}
	}

	@Test
	public void testGenerateCertificate() throws Exception {
		CertRASession certRASession = new CertRASession("info@e-contract.be", "0478/299492");

		String ssin = CertRAClient.getSSIN(this.signCertificateChain.get(0));

		X500NameBuilder nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(X509ObjectIdentifiers.countryName, new DERPrintableString("BE"));
		nameBuilder.addRDN(X509ObjectIdentifiers.organization, new DERPrintableString("Federal Government"));
		nameBuilder.addRDN(X509ObjectIdentifiers.organizationalUnitName,
				new DERPrintableString("eHealth-platform Belgium"));
		nameBuilder.addRDN(X509ObjectIdentifiers.organizationalUnitName, new DERPrintableString("SSIN=" + ssin));
		nameBuilder.addRDN(X509ObjectIdentifiers.commonName, new DERPrintableString("SSIN=" + ssin));
		X500Name name = nameBuilder.build();
		byte[] encodedCsr = certRASession.generateCSR(name);

		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(encodedCsr);
		LOG.debug("CSR subject: " + csr.getSubject());
		X500Name subjectName = csr.getSubject();
		RDN[] rdns = subjectName.getRDNs();
		for (RDN rdn : rdns) {
			LOG.debug("--------");
			AttributeTypeAndValue[] attributes = rdn.getTypesAndValues();
			for (AttributeTypeAndValue attribute : attributes) {
				LOG.debug(attribute.getType() + " = " + attribute.getValue());
				LOG.debug("value type: " + attribute.getValue().getClass().getName());
			}
		}
	}
}
