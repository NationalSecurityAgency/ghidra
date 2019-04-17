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

/**
 * This class represents a numbered namespace (wiki page parlance) within a name of a
 *  Microsoft mangled symbol.
 */
public class MDNumberedNamespace extends MDParsableItem {
	private String name;

	public MDNumberedNamespace(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		MDEncodedNumber num = new MDEncodedNumber(dmang);
		num.parse();
		name = "`" + num + "'";
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, name);
	}
}

/******************************************************************************/
/******************************************************************************/
