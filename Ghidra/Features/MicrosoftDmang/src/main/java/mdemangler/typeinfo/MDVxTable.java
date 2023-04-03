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
package mdemangler.typeinfo;

import java.util.ArrayList;
import java.util.List;

import mdemangler.*;
import mdemangler.datatype.modifier.MDCVMod;
import mdemangler.naming.MDQualification;

/**
 * This is the base class for MDVfTable and MDVxTable.  Neither of these
 * derivatives actually do anything at this time, but they are two very
 * different types of tables in C++ and serve as place holders for future
 * processing.  I created MDVxTable, where the 'x' is 'b' or 'f' of
 * MDVbTable or MDVfTable, respectively.
 */
public class MDVxTable extends MDTypeInfo {

	private MDCVMod cvmod;
	private List<MDQualification> nestedQualifications;
	private boolean goodNestedTermination;

	// String name = "";

	public MDVxTable(MDMang dmang) {
		super(dmang);
		mdtype = new MDType(dmang);
		cvmod = new MDCVMod(dmang);
		nestedQualifications = new ArrayList<>();
		goodNestedTermination = false;
	}

	public MDCVMod getCVMod() {
		return cvmod;
	}

	/**
	 * Returns the list of MDQualification that I believe show the nested ownership within
	 * class parents
	 * @return the list of qualifications
	 */
	public List<MDQualification> getNestedQualifications() {
		return nestedQualifications;
	}

	public boolean isConst() {
		return cvmod.isConst();
	}

	public boolean isVolatile() {
		return cvmod.isVolatile();
	}

	public boolean isPointer64() {
		return cvmod.isPointer64();
	}

	@Override
	public void insert(StringBuilder builder) {
		cvmod.insert(builder);
	}

	// Found on 20140327:
	//  "??_7testAccessLevel@@6B@" = "const testAccessLevel::`vftable'"
	// Found on 20140521 (Win7):
	//  "??_7CAnalogAudioStream@@6BCUnknown@@CKsSupport@@@", discovered nesting
	@Override
	protected void parseInternal() throws MDException {
		cvmod.parse();
		while ((dmang.peek() != '@') && (dmang.peek() != MDMang.DONE)) {
			MDQualification qualification = new MDQualification(dmang);
			qualification.parse();
			nestedQualifications.add(qualification);
		}
		// The first @ terminates the qualifier, the second terminates the qualified name
		// (which is a list of qualifiers).  If there is a third, it likely terminates the
		// list of qualified names outside of the MDVxTable.
		if (dmang.peek() == '@') {
			dmang.increment();
			goodNestedTermination = true;
		}
		nameModifier = generateNameModifier();
	}

	String generateNameModifier() {
		if (!goodNestedTermination) {
			return "{for ??}";
		}
		if (nestedQualifications.isEmpty()) {
			return "";
		}

		boolean first = true;
		StringBuilder modNameBuilder = new StringBuilder();
		dmang.appendString(modNameBuilder, "{for `");
		for (MDQualification qualification : nestedQualifications) {
			StringBuilder qnameBuilder = new StringBuilder();
			qualification.insert(qnameBuilder);
			if (first) {
				first = false;
			}
			else {
				dmang.appendString(modNameBuilder, "'s `");
			}
			dmang.appendString(modNameBuilder, qnameBuilder.toString());
		}
		dmang.appendString(modNameBuilder, "'}");
		return modNameBuilder.toString();
	}

}

/******************************************************************************/
/******************************************************************************/
