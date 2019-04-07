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
 * This class represents a std::nullptr_t type within a Microsoft mangled symbol.
 * It is one of a number of "extended" data types not originally planned by Microsoft.
 */
public class MDStdNullPtrType extends MDModifierType {

	private static final String modifierTypeName = "std::nullptr_t";

	public MDStdNullPtrType(MDMang dmang) {
		super(dmang, 3);
	}

	@Override
	protected void parseInternal() throws MDException {
		cvMod.setOtherType();
	}

	@Override
	public void insert(StringBuilder builder) {
		builder.setLength(0);
		dmang.appendString(builder, modifierTypeName); // TODO: consider moving string here.
	}
}

/******************************************************************************/
/******************************************************************************/
