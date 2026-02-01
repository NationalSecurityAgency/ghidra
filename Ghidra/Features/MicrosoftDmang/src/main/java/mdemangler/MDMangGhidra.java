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

import mdemangler.datatype.MDDataType;

/**
 * A new built-from-scratch class for demangling debug symbols created using
 * Microsoft Visual Studio.
 * <p>
 * Note: the processing of {@link MDParsableItem} that was in this class was moved to a
 * package-projected utility class of the MicrosoftDemangler.  Ghidra users should defer to
 * using the MicrosoftDemangler.
 * <p>
 * This {@link MDMangGhidra} class might be removed in the future, with deferred use to MDMang.
 */
public class MDMangGhidra extends MDMang {

	private boolean demangleOnlyKnownPatterns = false;

	//==============================================================================================
	// Control

	/**
	 * Controls whether a symbol is skipped (returns null) if it doesn't match a known mangling
	 * pattern, which is generally the start pattern of a symbol.  Default is {@code false}
	 * @param demangleOnlyKnownPatternsArg {@code true} to skip a symbol that doesn't match a
	 * known pattern
	 */
	public void setDemangleOnlyKnownPatterns(boolean demangleOnlyKnownPatternsArg) {
		demangleOnlyKnownPatterns = demangleOnlyKnownPatternsArg;
	}

	/**
	 * Returns {@code true} if the process will skip a symbol that doesn't match a known pattern
	 * @return {@code true} if a symbol that doesn't a known pattern will be skipped
	 */
	public boolean demangleOnlyKnownPatterns() {
		return demangleOnlyKnownPatterns;
	}

	//==============================================================================================
	@Override
	public MDParsableItem demangle() throws MDException {
		if (demangleOnlyKnownPatterns) {
			if (!(mangled.startsWith("?") || mangled.startsWith(".") || mangled.startsWith("_") ||
				(mangled.charAt(0) < 'a') ||
				(mangled.charAt(0) >= 'a') && (mangled.charAt(0) <= 'z') ||
				(mangled.charAt(0) >= 'A') && (mangled.charAt(0) <= 'Z'))) {
				return null;
			}
		}
		MDParsableItem returnedItem = super.demangle();
		// TODO: Investigate... seems that mangledSource should be eliminated throughout and
		// that mangled should be used instead.
		return returnedItem;
	}

	@Override
	public MDDataType demangleType() throws MDException {
		MDDataType returnedType = super.demangleType();
		return returnedType;
	}

}
