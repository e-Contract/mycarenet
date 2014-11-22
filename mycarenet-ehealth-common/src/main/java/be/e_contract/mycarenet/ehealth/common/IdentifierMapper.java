/*
 * Java MyCareNet Project.
 * Copyright (C) 2013 e-Contract.be BVBA.
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

/**
 * This identifier mapper can map from eHealthBox identifiers to ETK
 * identifiers.
 * 
 * @author Frank Cornelis
 * 
 */
public class IdentifierMapper {

	/**
	 * Maps from eHealthBox identifier types to ETK identifier types.
	 * 
	 * @param eHealthBoxType
	 * @param eHealthBoxQuality
	 * @return the corresponding ETK identifier type.
	 */
	public static String getETKIdentifierType(String eHealthBoxType,
			String eHealthBoxQuality) {
		if ("INSS".equals(eHealthBoxType)) {
			return "SSIN";
		}
		if ("CBE".equals(eHealthBoxType)) {
			return "CBE";
		}
		if ("FAMPH".equals(eHealthBoxType)) {
			return "NIHII-PHARMACY";
		}
		// else NIHII
		if (null != eHealthBoxQuality) {
			if ("HOSPITAL".equalsIgnoreCase(eHealthBoxQuality)) {
				return "NIHII-HOSPITAL";
			}
			if ("LABO".equals(eHealthBoxQuality)) {
				return "NIHII-LABO";
			}
			if ("RETIREMENT".equals(eHealthBoxQuality)) {
				return "NIHII-RETIREMENT";
			}
			if ("OTD_PHARMACY".equals(eHealthBoxQuality)) {
				return "NIHII-OTD_PHARMACY";
			}
			if ("GROUP".equals(eHealthBoxQuality)) {
				return "NIHII-GROUP";
			}
		}
		return "NIHII";
	}
}
