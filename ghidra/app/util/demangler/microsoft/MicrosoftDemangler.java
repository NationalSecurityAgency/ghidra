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

import java.util.regex.Pattern;

import ghidra.app.util.demangler.*;
import ghidra.app.util.opinion.MSCoffLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import mdemangler.MDException;
import mdemangler.MDMangGhidra;
import util.demangler.GenericDemangledException;

/**
 * A class for demangling debug symbols created using Microsoft Visual Studio.
 */
public class MicrosoftDemangler implements Demangler {

	/** 
	 * This represents an odd symbol that looks mangled, but we don't know what to do with.  It
	 * is of the form:
	 * 		?BobsStuffIO@344text__@@U_text@@?W
	 * 
	 * where the last character is preceded by a special character, such as ?, *, -, etc
	 */
	private static Pattern INVALID_TRAILING_CHARS_PATTERN = Pattern.compile(".*@@[?*`%~+/-][A-Z]");

	public MicrosoftDemangler() {
	}

	@Override
	public boolean canDemangle(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1 ||
			executableFormat.indexOf(MSCoffLoader.MSCOFF_NAME) != -1);
	}

	@Override
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		try {
			DemangledObject demangled = demangleMS(mangled, demangleOnlyKnownPatterns);
			return demangled;
		}
		catch (GenericDemangledException e) {
			throw new DemangledException(true);
		}
	}

	private DemangledObject demangleMS(String mangled, boolean demangleOnlyKnownPatterns)
			throws GenericDemangledException {
		if (mangled == null || mangled.length() == 0) {
			throw new GenericDemangledException(true);
		}

		MDMangGhidra demangler = new MDMangGhidra();
		try {
			demangler.demangle(mangled, demangleOnlyKnownPatterns); //not using return type here.
			DemangledObject object = demangler.getObject();
			return object;
		}
		catch (MDException e) {
			GenericDemangledException gde =
				new GenericDemangledException("Unable to demangle symbol: " + mangled);
			gde.initCause(e);
			throw gde;
		}
	}

//	private boolean isMangled(String mangled) {
//		int atpos = mangled.indexOf("@");
//		boolean isMangled = mangled.charAt(0) == '?' && atpos != -1;
//
//		if (!isMangled) {
//			return false;
//		}
//
//		if (mangled.endsWith("~")) {
//			return false;
//		}
//
//		//
//		// Now check for some odd things that we've seen.
//		//
//		Matcher matcher = INVALID_TRAILING_CHARS_PATTERN.matcher(mangled);
//		if (matcher.matches()) {
//			return false;
//		}
//
//		return true;
//	}
}
