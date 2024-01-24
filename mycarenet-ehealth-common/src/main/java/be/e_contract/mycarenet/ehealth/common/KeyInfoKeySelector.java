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
package be.e_contract.mycarenet.ehealth.common;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSR105 key selector implementation using the ds:KeyInfo data of the signature
 * itself.
 *
 * @author Frank Cornelis
 *
 */
public class KeyInfoKeySelector extends KeySelector implements KeySelectorResult {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyInfoKeySelector.class);

    protected X509Certificate certificate;

    @Override
    public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {
        LOGGER.debug("select key");
        this.certificate = null;
        if (null == keyInfo) {
            throw new KeySelectorException("no ds:KeyInfo present");
        }
        List<XMLStructure> keyInfoContent = keyInfo.getContent();
        for (XMLStructure keyInfoStructure : keyInfoContent) {
            if (false == (keyInfoStructure instanceof X509Data)) {
                continue;
            }
            X509Data x509Data = (X509Data) keyInfoStructure;
            List<Object> x509DataList = x509Data.getContent();
            for (Object x509DataObject : x509DataList) {
                if (false == (x509DataObject instanceof X509Certificate)) {
                    continue;
                }
                this.certificate = (X509Certificate) x509DataObject;
                LOGGER.debug("signer certificate: {}", this.certificate.getSubjectX500Principal());
                return this;
            }
        }
        throw new KeySelectorException("No key found!");
    }

    @Override
    public Key getKey() {
        return this.certificate.getPublicKey();
    }

    /**
     * Gives back the X509 certificate used during the last signature
     * verification operation.
     *
     * @return
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }
}
