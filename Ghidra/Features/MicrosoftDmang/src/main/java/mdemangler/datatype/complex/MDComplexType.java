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
package mdemangler.datatype.complex;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.datatype.MDDataType;
import mdemangler.naming.MDQualifiedName;

/**
 * This class represents the base class of a number of "complex" data types
 * within a Microsoft mangled symbol.  The term "complex" has nothing to do
 * with complex numbers.
 */
public class MDComplexType extends MDDataType {
	private MDQualifiedName qualifiedName;

	public MDComplexType(MDMang dmang) {
		this(dmang, 1);
	}

	public MDComplexType(MDMang dmang, int startIndexOffset) {
		super(dmang, startIndexOffset);
		qualifiedName = new MDQualifiedName(dmang);
	}

	@Override
	public String getTypeName() {
		return "";
	}

	public String getTypeNamespace() {
		return qualifiedName.toString();
	}

	public MDQualifiedName getNamespace() {
		return qualifiedName;
	}

	@Override
	protected void parseInternal() throws MDException {
		qualifiedName.parse();
	}

	@Override
	public void insert(StringBuilder builder) {
		// TODO: look at what needs to be done to get rid of this?
		if ((builder.length() != 0) && (builder.charAt(0) != ' ')) {
			dmang.insertString(builder, " ");
		}
		qualifiedName.insert(builder);
		super.insert(builder);
	}
}
