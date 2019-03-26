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

import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.listing.Program;

public class NameVersions {
	public String rawName;			// Original name
	public String similarName;		// Name with underscores removed
	public String demangledBaseName;	// Base name of the demangled string
	
	public NameVersions(String raw) {
		rawName = raw;
		similarName = null;
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

	public static NameVersions generate(String rawName,Program program) {
		NameVersions result = new NameVersions(rawName);
		if (rawName != null) {
			DemangledObject demangledObj = demangle(program, rawName);
			if (demangledObj != null) {
				result.demangledBaseName = demangledObj.getName().replaceFirst("_*", "");
			}
	
			// Put base names with underscores removed in a HashSet
			result.similarName = rawName.replaceFirst("_*", "");
		}
		return result;
	}
}
