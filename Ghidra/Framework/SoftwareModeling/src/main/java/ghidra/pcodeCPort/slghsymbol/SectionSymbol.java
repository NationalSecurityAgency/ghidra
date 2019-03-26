/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.slghsymbol;

import ghidra.sleigh.grammar.Location;

// Named p-code sections
public class SectionSymbol extends SleighSymbol {
	private int templateid;   // Index into the ConstructTpl array
	private int define_count; // Number of definitions of this named section
	private int ref_count;    // Number of references to this named section

	public SectionSymbol(Location loc, String nm, int id) {
		super(loc, nm);
		templateid = id;
		define_count = 0;
		ref_count = 0;
	}

	public int getTemplateId() {
		return templateid;
	}

	public void incrementDefineCount() {
		define_count += 1;
	}

	public void incrementRefCount() {
		ref_count += 1;
	}

	public int getDefineCount() {
		return define_count;
	}

	public int getRefCount() {
		return ref_count;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.section_symbol;
	}
	// Not saved or restored
}
