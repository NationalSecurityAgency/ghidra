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
package ghidra.feature.fid.service;

import ghidra.app.util.demangler.*;
import ghidra.program.model.listing.Program;

public class NameVersions {
	public String rawName;			// Original name
	public String similarName;		// Name with underscores removed
	public String demangledNoTemplate;	// Demangled string with (first) template removed
	public String demangledBaseName;	// Base name of the demangled string
	public String demangledFull;	// The full demangled signature
	
	public NameVersions(String raw) {
		rawName = raw;
		similarName = null;
		demangledNoTemplate = null;
		demangledBaseName = null;
	}

	public static DemangledObject demangle(Program program, String mangledName) {
		DemangledObject demangledObj = null;
		try {
			demangledObj = DemanglerUtil.demangle(program, mangledName);
		}
		catch (Exception e) {
			// log.appendMsg("Unable to demangle: "+info.getName());
		}
		if (demangledObj != null) {
			return demangledObj;
		}
		return null;
	}

	private static String getBaseClass(Demangled namespace) {
		String name = namespace.getNamespaceName();		// First level of namespace
		// Check for evidence of anonymous or unnamed namespace, which won't be distinguishing
		if (name.length() > 1 && name.charAt(0) == '`') {
			char firstChar = name.charAt(1);
			if (firstChar >= '0' && firstChar <= '9') {
				return namespace.getNamespaceString();	// Get full namespace
			}
		}
		return name;
	}

	/**
	 * If there exists an initial set of template parameters bracketed by '<' and '>'
	 * in the given demangled name, strip them.
	 * @param demangledObj is the object holding the demangled name
	 * @return the stripped name or null if no parameters present
	 */
	private static String removeTemplateParams(DemangledObject demangledObj) {
		String name = demangledObj.getDemangledName();
		int pos1 = name.indexOf('<');
		if (pos1 < 0) {
			return null;
		}
		int nesting = 1;
		int pos2;
		for (pos2 = pos1 + 1; pos2 < name.length(); ++pos2) {
			char c = name.charAt(pos2);
			if (c == '<') {
				nesting += 1;
			}
			else if (c == '>') {
				nesting -= 1;
				if (nesting == 0) {
					break;
				}
			}
		}
		if (nesting != 0) {
			return null;
		}
		return name.substring(0, pos1 + 1) + name.substring(pos2);
	}

	private static String constructBaseName(DemangledObject demangledObj) {
		String origName = demangledObj.getName();
		String name = origName.replaceFirst("_*", "");
		Demangled namespace = demangledObj.getNamespace();
		if (namespace != null) {
			if (name.endsWith("destructor'") ||
				name.startsWith("operator") ||
				name.startsWith("dtor$")) {
				String baseClassName = getBaseClass(namespace);
				if (baseClassName == null) {
					return null;
				}
				return baseClassName + "::" + origName;
			}
			String fullString = namespace.getNamespaceString();
			if (fullString != null && fullString.startsWith("std::")) {
				// Common containers, make sure we keep the whole name
				if (fullString.startsWith("std::vector") || fullString.startsWith("std::list") ||
					fullString.startsWith("std::map") || fullString.startsWith("std::set") ||
					fullString.startsWith("std::basic_string")) {
					return fullString + "::" + origName;
				}
			}
		}
		return name;
	}

	public static NameVersions generate(String rawName,Program program) {
		NameVersions result = new NameVersions(rawName);
		if (rawName != null) {
			DemangledObject demangledObj = demangle(program, rawName);
			if (demangledObj != null) {
				result.demangledFull = demangledObj.getOriginalDemangled();
				result.demangledNoTemplate = removeTemplateParams(demangledObj);
				result.demangledBaseName = constructBaseName(demangledObj);
			}
	
			// Put base names with underscores removed in a HashSet
			result.similarName = rawName.replaceFirst("_*", "");
		}
		return result;
	}
}
