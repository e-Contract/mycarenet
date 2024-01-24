/*
 * Java MyCareNet Project.
 * Copyright (C) 2023 e-Contract.be BV.
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
package test.integ.be.e_contract.ehealth.sts;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import be.e_contract.ehealth.sts.Claim;
import be.e_contract.ehealth.sts.EHealthWSTrustSTSClient;
import be.e_contract.mycarenet.ehbox.EHealthBoxConsultationClient;
import be.e_contract.mycarenet.ehealth.common.AssertionVerifier;
import be.fedict.commons.eid.jca.BeIDProvider;
import test.integ.be.e_contract.mycarenet.Config;

public class EHealthWSTrustSTSClientTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(EHealthWSTrustSTSClientTest.class);

	private Config config;

	@BeforeAll
	public static void registerSecurityProviders() throws Exception {
		Security.addProvider(new BeIDProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testDirectToken() throws Exception {
		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(alias,
				this.config.getEHealthPKCS12Password().toCharArray());
		LOGGER.debug("eHealth X509: {}", eHealthCertificate);
		eHealthCertificate.checkValidity();
		String ssin = getSSIN(eHealthCertificate);

		EHealthWSTrustSTSClient client = new EHealthWSTrustSTSClient(
				"https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");
		client.setCredentials(eHealthPrivateKey, eHealthCertificate);
		client.setTracing("e-Contract.be", "info@e-contract.be");
		List<Claim> claims = new LinkedList<>();
		claims.add(new Claim("urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin));
		claims.add(new Claim("urn:be:fgov:person:ssin", ssin));
		claims.add(new Claim("urn:be:fgov:person:ssin:nurse:boolean"));
		Element assertion = client.issueAssertion(eHealthCertificate, claims);
		assertNotNull(assertion);
		LOGGER.debug("assertion: {}", client.toString(assertion));
		AssertionVerifier assertionVerifier = new AssertionVerifier(assertion);
		assertionVerifier.verify();
	}

	@Test
	public void testSignChallenge() throws Exception {
		KeyStore eHealthKeyStore = KeyStore.getInstance("PKCS12");
		FileInputStream fileInputStream = new FileInputStream(this.config.getEHealthPKCS12Path());
		eHealthKeyStore.load(fileInputStream, this.config.getEHealthPKCS12Password().toCharArray());
		Enumeration<String> aliasesEnum = eHealthKeyStore.aliases();
		String alias = aliasesEnum.nextElement();
		X509Certificate eHealthCertificate = (X509Certificate) eHealthKeyStore.getCertificate(alias);
		PrivateKey eHealthPrivateKey = (PrivateKey) eHealthKeyStore.getKey(alias,
				this.config.getEHealthPKCS12Password().toCharArray());
		LOGGER.debug("eHealth X509: {}", eHealthCertificate);
		eHealthCertificate.checkValidity();
		String ssin = getSSIN(eHealthCertificate);

		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey authnPrivateKey = (PrivateKey) keyStore.getKey("Authentication", null);
		X509Certificate authnCertificate = (X509Certificate) keyStore.getCertificate("Authentication");

		EHealthWSTrustSTSClient client = new EHealthWSTrustSTSClient(
				"https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");
		client.setCredentials(eHealthPrivateKey, eHealthCertificate);
		client.setChallengeCredentials(authnPrivateKey, authnCertificate);
		client.setTracing("e-Contract.be", "info@e-contract.be");
		List<Claim> claims = new LinkedList<>();
		claims.add(new Claim("urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin));
		claims.add(new Claim("urn:be:fgov:person:ssin", ssin));
		claims.add(new Claim("urn:be:fgov:person:ssin:nurse:boolean"));
		Element assertion = client.issueAssertion(authnCertificate, claims);
		assertNotNull(assertion);
		LOGGER.debug("assertion: {}", client.toString(assertion));

		AssertionVerifier assertionVerifier = new AssertionVerifier(assertion);
		X509Certificate samlSignerCertificate = assertionVerifier.verify();
		LOGGER.debug("SAML signer: {}", samlSignerCertificate.getSubjectX500Principal());
		LOGGER.debug("SAML not after: {}", assertionVerifier.getNotAfter());

		EHealthBoxConsultationClient eHealthBoxClient = new EHealthBoxConsultationClient(
				"https://services-acpt.ehealth.fgov.be/ehBoxConsultation/v3");
		eHealthBoxClient.setCredentials(eHealthPrivateKey, client.toString(assertion));
		eHealthBoxClient.getBoxInfo();
	}

	private String getSSIN(X509Certificate eHealthCertificate) {
		X500Principal userPrincipal = eHealthCertificate.getSubjectX500Principal();
		X500Name x500Name = new X500Name(userPrincipal.getName());
		RDN[] rdns = x500Name.getRDNs(BCStyle.CN);
		String name = IETFUtils.valueToString(rdns[0].getFirst().getValue());
		LOGGER.debug("CN: {}", name);
		String ssin = name.substring("SSIN\\=".length());
		LOGGER.debug("SSIN: {}", ssin);
		return ssin;
	}
}
