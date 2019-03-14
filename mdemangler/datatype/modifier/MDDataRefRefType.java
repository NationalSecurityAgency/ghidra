/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mdemangler.datatype.modifier;

import mdemangler.MDException;
import mdemangler.MDMang;

/**
 * This class represents a "data ref ref" data type within a Microsoft mangled symbol.
 * It is one of a number of "extended" data types not originally planned by Microsoft.
 */
// Added 20170330
//  TODO: Not sure what this is and Not sure of all the intricacies.
//     ...but checked that these are all allowed: EIF, CV (ABCD), array property, maanaged
//     properties
//  TODO: Seems very closely related to a "reference" type, so might find a way to merge
//     reference types together.
public class MDDataRefRefType extends MDModifierType {

	public MDDataRefRefType(MDMang dmang) {
		super(dmang, 3);
	}

	@Override
	protected void parseInternal() throws MDException {
		cvMod.setRefRefTemplateParameter();
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
