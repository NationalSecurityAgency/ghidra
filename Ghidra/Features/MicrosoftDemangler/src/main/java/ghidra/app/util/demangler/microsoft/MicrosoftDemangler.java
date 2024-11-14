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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import mdemangler.*;
import mdemangler.datatype.MDDataType;

/**
 * A class for demangling debug symbols created using Microsoft Visual Studio.
 */
public class MicrosoftDemangler implements Demangler {

	private MDMangGhidra demangler;
	private MDParsableItem item;
	private DemangledObject object;
	private MDDataType mdType;
	private DemangledDataType dataType;

	public MicrosoftDemangler() {
	}

	// Note: Consider deprecating this method and creating one that takes the MangledContext.
	// Another option might be to find a smarter, utility method that contains the complete
	// knowledge of when a particular demangler is appropriate.. but that would have to consider
	// demanglers written by others.
	@Override
	public boolean canDemangle(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1 ||
			executableFormat.indexOf(MSCoffLoader.MSCOFF_NAME) != -1);
	}

	@Override
	public DemangledObject demangle(MangledContext context) throws DemangledException {
		if (!(context instanceof MicrosoftMangledContext mContext)) {
			throw new DemangledException("Wrong context type");
		}
		if (!(context.getOptions() instanceof MicrosoftDemanglerOptions options)) {
			throw new DemangledException("MicrosoftDemanglerOptions expected");
		}
		String mangled = context.getMangled();

		demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(options.errorOnRemainingChars());
		demangler.setDemangleOnlyKnownPatterns(options.demangleOnlyKnownPatterns());
		demangler.setArchitectureSize(mContext.getArchitectureSize());
		demangler.setIsFunction(mContext.shouldInterpretAsFunction());
		try {
			item = demangler.demangle();
			if (item == null) {
				return null;
			}
			String originalDemangled = item.toString();
			demangler.getOutputOptions().setUseEncodedAnonymousNamespace(true);
			object =
				MicrosoftDemanglerUtil.convertToDemangledObject(item, mangled, originalDemangled);
			if (object != null) {
				object.setMangledContext(context);
			}
			return object;
		}
		catch (MDException e) {
			DemangledException de = new DemangledException(true);
			de.initCause(e);
			throw de;
		}
	}

	/**
	 * Attempts to demangle the type string of the mangled context into a type
	 *
	 * @param context the mangled context
	 * @return the result
	 * @throws DemangledException if the string cannot be demangled
	 */
	public DemangledDataType demangleType(MangledContext context) throws DemangledException {
		if (!(context instanceof MicrosoftMangledContext mContext)) {
			throw new DemangledException("Wrong context type");
		}
		if (!(context.getOptions() instanceof MicrosoftDemanglerOptions options)) {
			throw new DemangledException("MicrosoftDemanglerOptions expected");
		}
		String mangled = context.getMangled();

		demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(options.errorOnRemainingChars());
		demangler.setDemangleOnlyKnownPatterns(options.demangleOnlyKnownPatterns());
		demangler.setArchitectureSize(mContext.getArchitectureSize());
		demangler.setIsFunction(mContext.shouldInterpretAsFunction());
		try {
			mdType = demangler.demangleType();
			if (mdType == null) {
				return null;
			}
			String originalDemangled = mdType.toString();
			demangler.getOutputOptions().setUseEncodedAnonymousNamespace(true);
			dataType = MicrosoftDemanglerUtil.convertToDemangledDataType(mdType, mangled,
				originalDemangled);
			if (dataType != null) {
				dataType.setMangledContext(context);
			}
			return dataType;
		}
		catch (MDException e) {
			DemangledException de = new DemangledException(true);
			de.initCause(e);
			throw de;
		}
	}

	/**
	 * Returns the {@link MDParsableItem} used in demangling to a {@link DemangledObject}
	 * @return the item; can be null if item wasn't demangled
	 */
	public MDParsableItem getMdItem() {
		return item;
	}

	/**
	 * Returns the {@link MDDataType} used in demangling to a @link DemangledDataType}
	 * @return the type; can be null if type wasn't demangled
	 */
	public MDDataType getMdType() {
		return mdType;
	}

	/**
	 * Creates default options for microsoft demangler
	 * @return the options
	 */
	@Override
	public MicrosoftDemanglerOptions createDefaultOptions() {
		return new MicrosoftDemanglerOptions();
	}

	/**
	 * Creates a microsoft mangled context
	 * @param mangled the mangled name
	 * @param options the demangler options; if null, the default options are created
	 * @param program the program; can be null
	 * @param address the address for the name in the program; can be null
	 * @return the mangled context
	 */
	@Override
	public MicrosoftMangledContext createMangledContext(String mangled, DemanglerOptions options,
			Program program, Address address) {
		return new MicrosoftMangledContext(program, getMicrosoftOptions(options), mangled, address);
	}

	private MicrosoftDemanglerOptions getMicrosoftOptions(DemanglerOptions options) {
		if (options instanceof MicrosoftDemanglerOptions mOptions) {
			return mOptions;
		}
		if (options == null) {
			return createDefaultOptions();
		}
		return new MicrosoftDemanglerOptions(options);
	}

}
