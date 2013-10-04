/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 Frank Cornelis.
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

package test.integ.be.e_contract.mycarenet.etk;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

import test.integ.be.e_contract.mycarenet.Config;
import be.e_contract.mycarenet.etk.EtkDepotClient;
import be.fedict.commons.eid.client.BeIDCard;
import be.fedict.commons.eid.client.BeIDCards;
import be.fedict.commons.eid.client.FileType;
import be.fedict.commons.eid.consumer.Identity;
import be.fedict.commons.eid.consumer.tlv.TlvParser;

public class EtkDepotClientTest {

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testClient() throws Exception {
		EtkDepotClient etkDepotClient = new EtkDepotClient(
				"https://wwwacc.ehealth.fgov.be/etkdepot_1_0/EtkDepotService");

		BeIDCards beIDCards = new BeIDCards();
		BeIDCard beIDCard = beIDCards.getOneBeIDCard();
		byte[] identityData = beIDCard.readFile(FileType.Identity);
		Identity identity = TlvParser.parse(identityData, Identity.class);

		String inss = identity.getNationalNumber();
		byte[] etk = etkDepotClient.getEtk(inss);

		assertNotNull(etk);
	}
}
