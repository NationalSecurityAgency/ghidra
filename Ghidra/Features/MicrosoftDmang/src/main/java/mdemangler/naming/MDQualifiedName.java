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
 * This class represents a qualified name (wiki page parlance) within a name of a
 *  Microsoft mangled symbol. Note that it is slightly different from MDQualifiedBasicName
 *  in that it has an MDReusableName (MDFragmentName) as its first component instead of
 *  an MDBasicName.
 */
public class MDQualifiedName extends MDParsableItem {
	private MDReusableName name;
	private MDQualification qualification;

	public MDQualifiedName(MDMang dmang) {
		super(dmang);
		name = new MDReusableName(dmang);
		qualification = new MDQualification(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		name.insert(builder);
		if (qualification.hasContent()) {
			dmang.insertString(builder, "::");
			qualification.insert(builder);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		name.parse();
		qualification.parse();
	}

	public String getName() {
		return name.toString();
	}

	public MDQualification getQualification() {
		return qualification;
	}
}

/******************************************************************************/
/******************************************************************************/
