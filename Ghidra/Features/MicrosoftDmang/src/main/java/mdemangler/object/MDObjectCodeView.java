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

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C++ object
 *  and an additional <b><code>"CV:"</code></b> prefix, which supposedly means that it came from
 *  a CodeView compiler (older version of compiler?).
 */
// TODO: Not sure what this is, so:
// - if it really is an object, then it probably needs a better name; 
// - if it doesn't belong here (i.e., might be part of MDObjectCPP), then it should be moved
//    there.
public class MDObjectCodeView extends MDObjectCPP {

	public MDObjectCodeView(MDMang dmang) {
		super(dmang);
	}

	public String getPrefix() {
		return "CV:";
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.insertSpacedString(builder, getPrefix());
	}

	@Override
	protected void parseInternal() throws MDException {
		if ((dmang.peek() != '?') && (dmang.peek(1) != '@')) {
			throw new MDException("Missing prefix in MDObjectCodeView parsing");
		}
		dmang.increment(); // Skip the ?.
		dmang.increment(); // Skip the @.
		super.parseInternal();
	}
}

/******************************************************************************/
/******************************************************************************/
