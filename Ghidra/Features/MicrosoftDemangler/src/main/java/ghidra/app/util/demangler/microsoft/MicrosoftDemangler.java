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
package ghidra.app.util.demangler.microsoft;

import ghidra.app.util.demangler.*;
import ghidra.app.util.opinion.MSCoffLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import mdemangler.MDException;
import mdemangler.MDMangGhidra;

/**
 * A class for demangling debug symbols created using Microsoft Visual Studio.
 */
public class MicrosoftDemangler implements Demangler {

	public MicrosoftDemangler() {
	}

	@Override
	public boolean canDemangle(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1 ||
			executableFormat.indexOf(MSCoffLoader.MSCOFF_NAME) != -1);
	}

	@Override
	@Deprecated(since = "9.2", forRemoval = true)
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		try {
			DemangledObject demangled = demangleMS(mangled, demangleOnlyKnownPatterns);
			return demangled;
		}
		catch (DemangledException e) {
			throw new DemangledException(true);
		}
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions options)
			throws DemangledException {

		try {
			DemangledObject demangled = demangleMS(mangled, options.demangleOnlyKnownPatterns());
			return demangled;
		}
		catch (DemangledException e) {
			throw new DemangledException(true);
		}
	}

	private DemangledObject demangleMS(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		if (mangled == null || mangled.length() == 0) {
			throw new DemangledException(true);
		}

		MDMangGhidra demangler = new MDMangGhidra();
		try {
			demangler.demangle(mangled, demangleOnlyKnownPatterns);
			DemangledObject object = demangler.getObject();
			return object;
		}
		catch (MDException e) {
			DemangledException de =
				new DemangledException("Unable to demangle symbol: " + mangled);
			de.initCause(e);
			throw de;
		}
	}
}
