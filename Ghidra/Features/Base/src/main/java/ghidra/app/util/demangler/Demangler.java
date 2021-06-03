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
package ghidra.app.util.demangler;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL DEMANGLER CLASSES MUST END IN "Demangler".  If not,
 * the ClassSearcher will not find them.
 */
public interface Demangler extends ExtensionPoint {

	public boolean canDemangle(Program program);

	/**
	 * Deprecated.  Use {@link #demangle(String)} or
	 *  {@link #demangle(String, DemanglerOptions)}.
	 *
	 * @param mangled the mangled string
	 * @param demangleOnlyKnownPatterns true signals to avoid demangling strings that do
	 *        not fit known demangled patterns for this demangler
	 * @return the result
	 * @throws DemangledException if the string cannot be demangled
	 * @deprecated see above
	 */
	@Deprecated(since = "9.2", forRemoval = true)
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException;

	/**
	 * Attempts to demangle the given string using the default options 
	 * ({@link #createDefaultOptions()}
	 * 
	 * @param mangled the mangled string
	 * @return the result
	 * @throws DemangledException if the string cannot be demangled
	 */
	public default DemangledObject demangle(String mangled) throws DemangledException {
		return demangle(mangled, createDefaultOptions());
	}

	/**
	 * Attempts to demangle the given string using the given options
	 * 
	 * @param mangled the mangled string
	 * @param options the options
	 * @return the result
	 * @throws DemangledException if the string cannot be demangled
	 */
	public DemangledObject demangle(String mangled, DemanglerOptions options)
			throws DemangledException;

	/**
	 * Creates default options for this particular demangler
	 * @return the options
	 */
	public default DemanglerOptions createDefaultOptions() {
		return new DemanglerOptions();
	}
}
