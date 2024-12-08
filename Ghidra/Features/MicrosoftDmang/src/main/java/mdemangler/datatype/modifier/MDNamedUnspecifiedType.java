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
import mdemangler.datatype.extended.MDExtendedType;
import mdemangler.naming.MDQualifiedName;

/**
 * This class represents an unspecified type with a name.  (The $$Y code.)
 * It is one of a number of "extended" data types not originally planned by Microsoft.
 */
public class MDNamedUnspecifiedType extends MDExtendedType {

	// Not sure what is allowed... not sure if it can have basic or special names... need to test

	// Not sure what is allowed... not sure if it can have basic or special names... need to test
	//  However, I've seen it closed with the "@@" which seems to indicate that it has
	//  a qualified name... an MDQualification seems fit, as we probably do not want basic/special
	//  names... not sure if it can be back-referenced, but should test this.
	private MDQualifiedName qualifiedName;

	public MDNamedUnspecifiedType(MDMang dmang) {
		super(dmang, 3);
	}

	@Override
	public String getTypeName() {
		return qualifiedName.toString();
	}

	@Override
	protected void parseInternal() throws MDException {
		qualifiedName = new MDQualifiedName(dmang);
		qualifiedName.parse();
	}

	public MDQualifiedName getQualifiedName() {
		return qualifiedName;
	}

}
