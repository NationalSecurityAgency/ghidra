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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.naming.MDFragmentName;

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C++ object
 *  and an additional bracketed prefix.  These were seen in a dumpbin of a source program that
 *  I created, but undname does not support the symbol.  I do not know what to call this type
 *  of object, so the name is descriptive for now.  Some bracketed prefix have been
 *  <b><code>[T2M]</code></b> and <b><code>[MEP]</code></b>, which we have gleaned by searching
 *  the Internet to possibly mean "Transition to Managed (code)" and "Managed Entry Point." 
 */
// TODO: Not sure what this is, so:
//   - if it really is an object, then it probably needs a better name; 
//   - if it doesn't belong here (i.e., might be part of MDObjectCPP), then it should be moved there.
public class MDObjectBracket extends MDObjectReserved {
	private MDFragmentName fragmentName;
	private MDObjectCPP objectCPP;
	private MDFragmentName dollarOption;

	public MDObjectBracket(MDMang dmang) {
		super(dmang);
	}

	public String getPrefix() {
		StringBuilder bracketBuilder = new StringBuilder();
		if (dollarOption != null) {
			dmang.insertString(bracketBuilder, "]");
			dollarOption.insert(bracketBuilder);
			dmang.insertString(bracketBuilder, "[");
		}
		dmang.insertString(bracketBuilder, "]");
		fragmentName.insert(bracketBuilder);
		dmang.insertString(bracketBuilder, "[");
		return bracketBuilder.toString();
	}

	public MDObjectCPP getObjectCPP() {
		return objectCPP;
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		objectCPP.insert(builder);
		dmang.insertSpacedString(builder, getPrefix());
	}

	@Override
	protected void parseInternal() throws MDException {
		if ((dmang.peek() != '_') && (dmang.peek(1) != '_')) {
			throw new MDException("Missing prefix in MDObjectBracket parsing");
		}
		dmang.increment(2); // Skip the two underscores.
		fragmentName = new MDFragmentName(dmang);
		fragmentName.parse();
		StringBuilder fragBuilder = new StringBuilder();
		fragmentName.insert(fragBuilder);
		fragmentName.setName(fragBuilder.toString().toUpperCase());
		// TODO: Not sure of what the contained types can be (CPP and C?) We are currently
		//  containing MDObjectCPP.
		objectCPP = new MDObjectCPP(dmang);
		objectCPP.parse();
		// MDMANG SPECIALIZATION USED.
		objectCPP = dmang.getEmbeddedObject(objectCPP);
	}
}

/******************************************************************************/
/******************************************************************************/
