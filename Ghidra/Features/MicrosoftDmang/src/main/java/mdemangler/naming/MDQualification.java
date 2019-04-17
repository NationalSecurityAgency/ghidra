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

import java.util.*;

import mdemangler.*;

/**
 * This class represents a namespace qualification.  It is composed of individual namespace
 * components (MDQualifier).
 */
public class MDQualification extends MDParsableItem implements Iterable<MDQualifier> {
	private List<MDQualifier> quals = new ArrayList<>();

	public MDQualification(MDMang dmang) {
		super(dmang);
	}

	public boolean hasContent() {
		return (quals.size() > 0);
	}

	@Override
	public void insert(StringBuilder builder) {
		// MDMANG SPECIALIZATION USED.
		dmang.insert(builder, this);
	}

	// TODO: Keep this and use for MD version of output down the road (perhaps both are placed
	//  into dispatcher model)
	public void insert_MdVersion(StringBuilder builder) {
		boolean isInterface = false;
		for (MDQualifier qual : quals) {
			// Results in brackets as follows:
			//   "Namespace[::InterfaceNameSpace]::BaseName"
			//   "InterfaceNamespace]::NameSpace::BaseName" --Note that MSFT does not include
			//     opening bracket here.
			if (isInterface) {
				dmang.insertString(builder, "[");
			}
			isInterface = qual.isInterface();
			if (isInterface) {
				dmang.insertString(builder, "]");
			}
			qual.insert(builder);
			if (quals.indexOf(qual) != (quals.size() - 1)) {
				dmang.insertString(builder, "::");
			}
		}
		if (isInterface) {
			dmang.insertString(builder, "[");
		}
	}

	// TODO: this is potential SPECIALIZATION for MDMangVS2015 (and others)
	public void insert_VSAll(StringBuilder builder) {
		boolean isInterface = false;
		for (MDQualifier qual : quals) {
			// Results in brackets as follows:
			//   "Namespace[::InterfaceNameSpace]::BaseName"
			//   "InterfaceNamespace]::NameSpace::BaseName" --Note that MSFT does not include
			//     opening bracket here.
			if (isInterface) {
				dmang.insertString(builder, "[");
			}
			isInterface = qual.isInterface();
			if (isInterface) {
				dmang.insertString(builder, "]");
			}
			qual.insert(builder);
			if (quals.indexOf(qual) != (quals.size() - 1)) {
				dmang.insertString(builder, "::");
			}
		}
	}

	public void insertHeadQualifier(StringBuilder builder) {
		if (quals.size() != 0) {
			quals.get(0).insert(builder);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		while ((dmang.peek() != MDMang.DONE) && (dmang.peek() != '@')) {
			MDQualifier qual = new MDQualifier(dmang);
			qual.parse();
			quals.add(qual);
		}
		if (dmang.peek() == '@') {
			dmang.increment(); // Skip past @.
		}
	}

	@Override
	public Iterator<MDQualifier> iterator() {
		return quals.iterator();
	}
}

/******************************************************************************/
/******************************************************************************/
