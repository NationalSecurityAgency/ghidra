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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL DEMANGLER CLASSES MUST END IN "Demangler".  If not,
 * the ClassSearcher will not find them.
 */
public interface Demangler extends ExtensionPoint {

	// Note: Consider deprecating this method and creating one that takes the MangledContext.
	// Another option might be to find a smarter utility method that contains the complete
	// knowledge of when a particular demangler is appropriate.. but that would have to consider
	// demanglers written by others.
	public boolean canDemangle(Program program);

	/**
	 * Attempts to demangle the given string using a context
	 * ({@link #createMangledContext(String, DemanglerOptions, Program, Address)} with
	 *  default options ({@link #createDefaultOptions()}.
	 *
	 * @param mangled the mangled string
	 * @return the result; {@code null} is possible if the mangled string is not supported
	 * @throws DemangledException if the string cannot be demangled
	 */
	public default DemangledObject demangle(String mangled) throws DemangledException {
		MangledContext mangledContext = createMangledContext(mangled, null, null, null);
		DemangledObject demangledObject = demangle(mangledContext);
		if (demangledObject != null && demangledObject.getMangledContext() == null) {
			demangledObject.setMangledContext(mangledContext);
		}
		return demangle(mangledContext);
	}

	/**
	 * Attempts to demangle the given string using the given options
	 *
	 * @param mangled the mangled string
	 * @param options the options
	 * @return the result; {@code null} is possible if the mangled string is not supported
	 * @throws DemangledException if the string cannot be demangled
	 * @deprecated Use {@link #demangle(String)} or {@link #demangle(MangledContext)}.
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	public default DemangledObject demangle(String mangled, DemanglerOptions options)
			throws DemangledException {
		MangledContext mangledContext = createMangledContext(mangled, options, null, null);
		DemangledObject demangledObject = demangle(mangledContext);
		if (demangledObject != null && demangledObject.getMangledContext() == null) {
			demangledObject.setMangledContext(mangledContext);
		}
		return demangle(mangledContext);
	}

	/**
	 * Attempts to demangle the string of the mangled context and sets the mangled context on
	 * the {@link DemangledObject}
	 *
	 * @param context the mangled context
	 * @return the result; {@code null} is possible if the mangled string is not supported
	 * @throws DemangledException if the string cannot be demangled
	 */
	public DemangledObject demangle(MangledContext context) throws DemangledException;

	/**
	 * Creates default options for this particular demangler
	 * @return the options
	 */
	public default DemanglerOptions createDefaultOptions() {
		return new DemanglerOptions();
	}

	/**
	 * Creates a mangled context
	 * @param mangled the mangled name
	 * @param options the demangler options; if null, the default options are created
	 * @param program the program; can be null
	 * @param address the address for the name in the program; can be null
	 * @return the mangled context
	 */
	public default MangledContext createMangledContext(String mangled, DemanglerOptions options,
			Program program, Address address) {
		if (options == null) {
			options = createDefaultOptions();
		}
		return new MangledContext(program, options, mangled, address);
	}

}
