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
package ghidra.app.util.demangler.gnu;

import java.io.File;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.util.demangler.*;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.Application;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;

/**
 * A class for demangling debug symbols created using GNU GCC.
 */
public class GnuDemangler implements Demangler {

	private static final String DWARF_REF = "DW.ref."; //dwarf debug reference
	private static final String GLOBAL_PREFIX = "_GLOBAL_";

	public GnuDemangler() {
		// needed to instantiate dynamically
	}

	@Override
	public DemanglerOptions createDefaultOptions() {
		return new GnuDemanglerOptions();
	}

	@Override
	public boolean canDemangle(Program program) {

		String executableFormat = program.getExecutableFormat();
		if (isELF(executableFormat) || isMacho(executableFormat)) {
			return true;
		}

		CompilerSpec spec = program.getCompilerSpec();
		String specId = spec.getCompilerSpecID().getIdAsString();
		if (!specId.toLowerCase().contains("windows")) {
			return true;
		}
		return false;
	}

	@Override
	@Deprecated(since = "9.2", forRemoval = true)
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDemangleOnlyKnownPatterns(demangleOnlyKnownPatterns);
		return demangle(mangled, options);
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions demanglerOtions)
			throws DemangledException {

		GnuDemanglerOptions options = getGnuOptions(demanglerOtions);
		if (skip(mangled, options)) {
			return null;
		}

		String originalMangled = mangled;
		String globalPrefix = null;
		if (mangled.startsWith(GLOBAL_PREFIX)) {
			int index = mangled.indexOf("_Z");
			if (index > 0) {
				globalPrefix = mangled.substring(0, index);
				mangled = mangled.substring(index);
			}
		}
		else if (mangled.startsWith("__Z")) {
			mangled = mangled.substring(1);//removed first underscore....
		}

		boolean isDwarf = false;
		if (mangled.startsWith(DWARF_REF)) {
			int len = DWARF_REF.length();
			mangled = mangled.substring(len);
			isDwarf = true;
		}

		try {

			GnuDemanglerNativeProcess process = getNativeProcess(options);
			String demangled = process.demangle(mangled).trim();
			if (mangled.equals(demangled) || demangled.length() == 0) {
				throw new DemangledException(true);
			}

			boolean onlyKnownPatterns = options.demangleOnlyKnownPatterns();
			DemangledObject demangledObject = parse(mangled, process, demangled, onlyKnownPatterns);
			if (demangledObject == null) {
				return demangledObject;
			}

			if (globalPrefix != null) {
				DemangledFunction dfunc = new DemangledFunction(originalMangled, demangled,
					globalPrefix + demangledObject.getName());
				dfunc.setNamespace(demangledObject.getNamespace());
				demangledObject = dfunc;
			}

			if (isDwarf) {
				DemangledAddressTable dat =
					new DemangledAddressTable(originalMangled, demangled, (String) null, false);
				dat.setSpecialPrefix("DWARF Debug ");
				dat.setName(demangledObject.getName());
				dat.setNamespace(demangledObject.getNamespace());
				return dat;
			}

			return demangledObject;
		}
		catch (IOException e) {
			if (e.getMessage().endsWith("14001")) {
				ResourceFile installationDir = Application.getInstallationDirectory();
				throw new DemangledException("Missing runtime libraries. " + "Please install " +
					installationDir + File.separatorChar + "support" + File.separatorChar +
					"install_windows_runtime_libraries.exe.");
			}
			throw new DemangledException(e);
		}
	}

	private GnuDemanglerOptions getGnuOptions(DemanglerOptions options) {

		if (options instanceof GnuDemanglerOptions) {
			return (GnuDemanglerOptions) options;
		}

		return new GnuDemanglerOptions(options);
	}

	private GnuDemanglerNativeProcess getNativeProcess(GnuDemanglerOptions options)
			throws IOException {

		String demanglerName = options.getDemanglerName();
		String applicationOptions = options.getDemanglerApplicationArguments();
		return GnuDemanglerNativeProcess.getDemanglerNativeProcess(demanglerName,
			applicationOptions);
	}

	/**
	 * Determines if the given mangled string should not be demangled.  There are a couple
	 * patterns that will always be skipped.
	 * If {@link GnuDemanglerOptions#demangleOnlyKnownPatterns()} is true, then only mangled
	 * symbols matching a list of known start patters will not be skipped.
	 *
	 * <P>This demangler class will default to demangling most patterns, since we do not yet
	 * have a comprehensive list of known start patterns.
	 *
	 * @param mangled the mangled string
	 * @param options the options
	 * @return true if the string should not be demangled
	 */
	private boolean skip(String mangled, GnuDemanglerOptions options) {

		// Ignore versioned symbols which are generally duplicated at the same address
		if (mangled.indexOf("@") > 0) { // do not demangle versioned symbols
			return true;
		}

		if (mangled.startsWith("___")) {
			// not a mangled symbol, but the demangler will try anyway, so don't let it
			return true;
		}

		if (!options.demangleOnlyKnownPatterns()) {
			return false; // let it go through
		}

		// This is the current list of known demangler start patterns.  Add to this list if we
		// find any other known GNU start patterns.
		if (mangled.startsWith("_Z")) {
			return false;
		}
		if (mangled.startsWith("__Z")) {
			return false;
		}
		if (mangled.startsWith("h__")) {
			return false; // not sure about this one
		}
		if (mangled.startsWith("?")) {
			return false; // not sure about this one
		}
		if (isGnu2Or3Pattern(mangled)) {
			return false;
		}

		return true;
	}

	private DemangledObject parse(String mangled, GnuDemanglerNativeProcess process,
			String demangled, boolean demangleOnlyKnownPatterns) {

		if (demangleOnlyKnownPatterns && !isKnownMangledString(mangled, demangled)) {
			return null;
		}

		GnuDemanglerParser parser = new GnuDemanglerParser();
		DemangledObject demangledObject = parser.parse(mangled, demangled);
		return demangledObject;
	}

	private boolean isKnownMangledString(String mangled, String demangled) {
		//
		// We get requests to demangle strings that are not mangled.   For newer mangled strings
		// we know how to avoid that.  However, older mangled strings can be of many forms.  To
		// detect whether a string is mangled, we have to resort to examining the output of
		// the demangler.
		//

		// check for the case where good strings have '__' in them (which is valid GNU2 mangling)
		if (isInvalidDoubleUnderscoreString(mangled, demangled)) {
			return false;
		}

		return true;
	}

	private boolean isInvalidDoubleUnderscoreString(String mangled, String demangled) {

		int index = mangled.indexOf("__");
		if (index == -1) {
			return false;
		}

		//
		// Bad string form:  text__moretext
		//
		// The demangler will output something like text(..)(...)(...) or e::text(...)(...)
		String leadingText = mangled.substring(0, index);
		return demangled.contains(leadingText);
	}

	private boolean isGnu2Or3Pattern(String mangled) {

		//@formatter:off
		return // Gnu2/3 constructs--not sure if we still need these
			   mangled.startsWith("_GLOBAL_.I.") ||
			   mangled.startsWith("_GLOBAL_.D.") ||
			   mangled.startsWith("_GLOBAL__I__Z") ||
			   mangled.startsWith("_GLOBAL__D__Z");
		//@formatter:on
	}

	private boolean isELF(String executableFormat) {
		return executableFormat != null && executableFormat.indexOf(ElfLoader.ELF_NAME) != -1;
	}

	private boolean isMacho(String executableFormat) {
		return executableFormat != null && executableFormat.indexOf(MachoLoader.MACH_O_NAME) != -1;
	}
}
