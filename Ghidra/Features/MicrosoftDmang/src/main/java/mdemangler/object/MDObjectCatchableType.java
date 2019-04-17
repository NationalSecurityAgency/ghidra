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

import java.util.*;

import mdemangler.MDException;
import mdemangler.MDMang;

/**
 * This class represents a MSFT <b><code>CatchableType</code></b> symbol.  We have created this
 *  object and the <b><code>MDObjectReserved</code></b> type from which it is derived.
 *  <b><code>CatchableType</code></b> seemingly has a structure as seen in the class layout of
 *  a 32-bit binary as follows:
 * <pre>
 *       class _s__CatchableType	size(28):
 *       +---
 *   0   | properties
 *   4   | pType
 *   8   | _PMD thisDisplacement
 *  20   | sizeOrOffset
 *  24   | copyFunction
 *       +---
 * </pre>
 * We have seen symbols with double underscore (usually 32-bit binary) and single underscore
 *  (usually 64-bit binary), such as:<pre>
 *   mangled = "__CT??_R0?AUX@@@81";
 *   or...
 *   mangled = "_CT??_R0?AUX@@@81";
 *   </pre>
 */
public class MDObjectCatchableType extends MDObjectReserved {
	private String digits;
	private List<MDObjectCPP> objectCPPList;

	public MDObjectCatchableType(MDMang dmang) {
		super(dmang);
		objectCPPList = new ArrayList<>();
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.appendString(builder, "[CatchableType," + digits + "]");
		Iterator<MDObjectCPP> iter = objectCPPList.iterator();
		while (iter.hasNext()) {
			MDObjectCPP objectCPP = iter.next();
			dmang.appendString(builder, "{" + objectCPP + "}");
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		//We have seen one or two items, seemingly MDObjectCPPs, and have no evidence
		// for the ability for there to be more, but we're using a list and looking
		// for more than two... just in case.  The "digits" only seem to come after
		// the last one.
		do {
			MDObjectCPP objectCPP = new MDObjectCPP(dmang);
			objectCPP.parse();
			// MDMANG SPECIALIZATION USED.
			objectCPP = dmang.getEmbeddedObject(objectCPP);
			objectCPPList.add(objectCPP);
			//We are assuming that we can have more than one digit.
			digits = parseDigits(dmang);
		}
		while ((dmang.peek() != MDMang.DONE) && digits.isEmpty());
	}
}

/******************************************************************************/
/******************************************************************************/
