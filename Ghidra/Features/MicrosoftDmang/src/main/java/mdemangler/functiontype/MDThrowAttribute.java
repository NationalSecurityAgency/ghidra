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
package mdemangler.functiontype;

import mdemangler.*;

/**
 * This class represents a throw attribute (Microsoft C++ mangling parlance)
 *  of a function within a Microsoft mangled symbol.
 */
public class MDThrowAttribute extends MDParsableItem {
	private MDArgumentsList argsList;
	private boolean hasThrow = true;

	public MDThrowAttribute(MDMang dmang) {
		super(dmang);
		argsList = new MDArgumentsList(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() == 'Z') {
			dmang.increment();
			hasThrow = false;
		}
		else {
			argsList.parse();
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (hasThrow) {
			dmang.appendString(builder, "throw(");
			argsList.insert(builder);
			dmang.appendString(builder, ")");
		}
	}
}

/******************************************************************************/
/******************************************************************************/
