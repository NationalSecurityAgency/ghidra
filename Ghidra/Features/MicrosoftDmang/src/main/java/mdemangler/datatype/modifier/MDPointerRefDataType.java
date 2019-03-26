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
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;

/**
 * This class represents a "pointer reference" data type within a Microsoft mangled symbol.
 * It is one of a number of "extended" data types not originally planned by Microsoft.
 */
// I currently do have a good name for this class.  It is the $$B type, which:
//   * has no CV (including no EIF and no Managed Properties)
//   * modifies a type
//     - the modified type is data
//   * can have an array property (as a data-modified type can)
// This can be seen as a template parameter, but can also be found as a direct data type.
// Perhaps this class name should be changed, once it is better understood.
public class MDPointerRefDataType extends MDModifierType {

	public MDPointerRefDataType(MDMang dmang) {
		super(dmang, 3);
		cvMod.setOtherType();
		cvMod.clearProperties();
		cvMod.clearCV();
	}

	@Override
	protected MDDataType parseReferencedType() throws MDException {
		return MDDataTypeParser.parseBasicDataType(dmang, false);
	}

	@Override
	protected void parseInternal() throws MDException {
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
