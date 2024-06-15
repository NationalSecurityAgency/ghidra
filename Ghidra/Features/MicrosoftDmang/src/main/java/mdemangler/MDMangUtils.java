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
package mdemangler;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.SymbolPath;
import mdemangler.datatype.complex.MDComplexType;
import mdemangler.datatype.modifier.MDModifierType;
import mdemangler.naming.*;
import mdemangler.object.MDObjectCPP;

/**
 * Utility class for MDMang users (and perhaps internal)
 */
public class MDMangUtils {

	private MDMangUtils() {
		// purposefully empty
	}

	/**
	 * Returns SymbolPath for the demangled item
	 * @param parsableItem the demangled item
	 * @return the symbol path
	 */
	public static SymbolPath getSymbolPath(MDParsableItem parsableItem) {
		return getSymbolPath(parsableItem, false);
	}

	/**
	 * Returns a more simple SymbolPath for the demangled item.  Any embedded object found at
	 * the main namespace level will have its namespace components retrieved and inserted
	 * appropriately in the main SymbolPath namespace.  However, embedded objects that are more
	 * deeply placed (such as when used for a template argument) don't and shouldn't take part
	 * in this simplification
	 * @param parsableItem the demangled item
	 * @return the symbol path
	 */
	public static SymbolPath getSimpleSymbolPath(MDParsableItem parsableItem) {
		return getSymbolPath(parsableItem, true);
	}

	private static SymbolPath getSymbolPath(MDParsableItem parsableItem, boolean simple) {
		List<String> parts = new ArrayList<>();
		// When simple is true, we need to recurse the nested hierarchy to pull the names
		// up to the main namespace level, so we set recurse = true
		recurseNamespace(parts, parsableItem, simple);
		SymbolPath sp = null;
		for (String part : parts) {
			sp = new SymbolPath(sp, part);
		}
		return sp;
	}

	private static void recurseNamespace(List<String> parts, MDParsableItem item,
			boolean recurseNested) {
		item = getReferencedType(item);
		String name;
		MDQualification qualification;
		if (item instanceof MDComplexType complexType) {
			MDQualifiedName qualName = complexType.getNamespace();
			name = qualName.getName();
			qualification = qualName.getQualification();
		}
		else if (item instanceof MDObjectCPP objCpp) {
			MDObjectCPP embeddedObj = objCpp.getEmbeddedObject();
			name = embeddedObj.getName();
			qualification = embeddedObj.getQualification();
		}
		else {
			return;
		}

		List<String> myParts = new ArrayList<>();
		// the qualification comes in reverse order... the last is nearest to namespace root
		for (MDQualifier qual : qualification) {
			if (qual.isNested() && recurseNested) {
				MDNestedName nestedName = qual.getNested();
				MDObjectCPP nestedObjCpp = nestedName.getNestedObject();
				List<String> nestedParts = new ArrayList<>();
				recurseNamespace(nestedParts, nestedObjCpp, recurseNested);
				myParts.addAll(0, nestedParts);
			}
			else if (qual.isAnon()) {
				myParts.add(0, qual.getAnonymousName());
			}
			else {
				myParts.add(0, qual.toString());
			}
		}
		myParts.add(name);
		parts.addAll(myParts);
	}

	// This method recurses
	private static MDParsableItem getReferencedType(MDParsableItem item) {
		if (item instanceof MDModifierType m) {
			return getReferencedType(m.getReferencedType());
		}
		return item;
	}

}
