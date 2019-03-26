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
package mdemangler.naming;

import mdemangler.*;
import mdemangler.object.MDObjectCPP;

/**
 * This class represents a nested name (wiki page parlance) within a name of a
 *  Microsoft mangled symbol.
 */
public class MDNestedName extends MDParsableItem {
	private MDObjectCPP objectCPP;
	private String mangled;

	public MDNestedName(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		// Do not do a pushModifierContext here.
		if (dmang.peek() != '?') {
			throw new MDException("Missing '?' in MDNestedName parsing");
		}
		dmang.increment(); // Skip the first '?'
		int beginIndex = dmang.getIndex();
		objectCPP = new MDObjectCPP(dmang); // There is another '?' processed here.
		objectCPP.parse();
		// MDMANG SPECIALIZATION USED.
		objectCPP = dmang.getEmbeddedObject(objectCPP);
		mangled = dmang.getMangledSymbol().substring(beginIndex, dmang.getIndex());
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, "'");
		dmang.insertString(builder, objectCPP.toString());
		dmang.insertString(builder, "`");
	}

	public String getMangled() {
		return mangled;
	}
}

/******************************************************************************/
/******************************************************************************/
