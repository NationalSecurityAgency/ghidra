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
package ghidra.app.plugin.core.analysis.rust.demangler;

import ghidra.app.util.demangler.*;
import ghidra.program.model.listing.Program;

/**
 * A class for demangling debug symbols created using rustc
 */
public class RustDemangler implements Demangler {

	public RustDemangler() {
		// needed to instantiate dynamically
	}

	@Override
	public DemanglerOptions createDefaultOptions() {
		return new RustDemanglerOptions();
	}

	@Override
	public boolean canDemangle(Program program) {
		String name = program.getCompiler();
		return name.contains("rustc");
	}

	@Override
	@Deprecated(since = "9.2", forRemoval = true)
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		return null;
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions options) {
		RustDemanglerOptions rustOptions = getRustOptions(options);

		if (skip(mangled, rustOptions)) {
			return null;
		}

		String demangled = null;

		if (rustOptions.getDemanglerFormat() == RustDemanglerFormat.LEGACY ||
			rustOptions.getDemanglerFormat() == RustDemanglerFormat.AUTO) {
			demangled = RustDemanglerLegacy.demangle(mangled);
		}

		if (rustOptions.getDemanglerFormat() == RustDemanglerFormat.V0 ||
			(rustOptions.getDemanglerFormat() == RustDemanglerFormat.AUTO && demangled == null)) {
			demangled = RustDemanglerV0.demangle(mangled);
		}

		RustDemanglerParser parser = new RustDemanglerParser();
		DemangledObject demangledObject = parser.parse(mangled, demangled);

		if (options.applyCallingConvention() && demangledObject instanceof DemangledFunction) {
			((DemangledFunction) demangledObject).setCallingConvention("rustcall");
		}

		return demangledObject;
	}

	private RustDemanglerOptions getRustOptions(DemanglerOptions options) {
		if (options instanceof RustDemanglerOptions) {
			return (RustDemanglerOptions) options;
		}

		return new RustDemanglerOptions(options);
	}

	/**
	 * Determines if the given mangled string should not be demangled, on the basis
	 * of if it has a known start pattern
	 * 
	 * @param mangled the mangled string
	 * @param options the options
	 * @return true if the string should not be demangled
	 */
	private boolean skip(String mangled, RustDemanglerOptions options) {

		// The current list of demangler start patterns

		if (!options.demangleOnlyKnownPatterns()) {
			return false;
		}

		return !isRustMangled(mangled);
	}

	/**
	 * Return true if the string is a mangled rust string in a rust program
	 * 
	 * @param mangled potential mangled string
	 * @return true if the string could be a mangled string in a rust program
	 */
	public static boolean isRustMangled(String mangled) {
		if (mangled.startsWith("_ZN")) {
			return true;
		}

		if (mangled.startsWith("__ZN")) {
			return true;
		}

		if (mangled.startsWith("_R")) {
			return true;
		}

		if (mangled.startsWith("__R")) {
			return true;
		}

		return false;
	}
}
