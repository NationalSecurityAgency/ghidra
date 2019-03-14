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
package mdemangler.datatype.extended;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;

/**
 * This class represents an W64 data type within a Microsoft mangled symbol.
 */
public class MDW64Type extends MDExtendedType { // TODO: Think this is correct... can recheck.
	private MDDataType datatype; // TODO: Think this is correct... can recheck.

	public MDW64Type(MDMang dmang) {
		super(dmang);
	}

	@Override
	public String getTypeName() {
		return "__w64";
	}

	@Override
	protected void parseInternal() throws MDException {
		datatype = MDDataTypeParser.parseBasicDataType(dmang, false);
		datatype.parse();
	}

	@Override
	public void insert(StringBuilder builder) {
		datatype.insert(builder);
		super.insert(builder);
	}
}
