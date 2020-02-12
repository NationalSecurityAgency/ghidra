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

import ghidra.app.util.demangler.DemanglerOptions;

/**
 * GNU demangler options
 */
public class GnuDemanglerOptions extends DemanglerOptions {

	/*
	 						Note!
		If you update the demangler versions, then you also must update the help (search the
		html files for the old version strings).
	 */

	/**
	 * Version 2.24 of the GNU demangler.  This version supports older formats and older bugs.
	 */
	public static final String GNU_DEMANGLER_V2_24 = "demangler_gnu_v2_24";

	/**
	 * Version 2.33.1 of the GNU demangler.  This version supports less formats than older versions.
	 */
	public static final String GNU_DEMANGLER_V2_33_1 = "demangler_gnu_v2_33_1";

	/**
	 * The default version to use of the GNU demangler
	 */
	public static final String GNU_DEMANGLER_DEFAULT = GNU_DEMANGLER_V2_33_1;

	private String demanglerName = GNU_DEMANGLER_DEFAULT;
	private String demanglerApplicationArguments;

	public GnuDemanglerOptions() {
		// use default values
	}

	public GnuDemanglerOptions(DemanglerOptions copy) {
		super(copy);

		if (copy instanceof GnuDemanglerOptions) {
			GnuDemanglerOptions gCopy = (GnuDemanglerOptions) copy;
			demanglerName = gCopy.demanglerName;
			demanglerApplicationArguments = gCopy.demanglerApplicationArguments;
		}
	}

	/**
	 * Returns the external demangler executable name to be used for demangling.  The 
	 * default value is {@link #GNU_DEMANGLER_DEFAULT}.
	 * @return the name
	 */
	public String getDemanglerName() {
		return demanglerName;
	}

	/**
	 * Sets the external demangler executable name to be used for demangling
	 * @param name the name
	 */
	public void setDemanglerName(String name) {
		this.demanglerName = name;
	}

	/**
	 * Returns the current arguments to be passed to the external demangler executable
	 * @return the arguments
	 */
	public String getDemanglerApplicationArguments() {
		return demanglerApplicationArguments;
	}

	/**
	 * Sets the arguments to be passed to the external demangler executable
	 * @param args the arguments
	 */
	public void setDemanglerApplicationArguments(String args) {
		this.demanglerApplicationArguments = args;
	}

	/**
	 * A convenience method to copy the state of this options object, changing the 
	 * demangler executable name to the deprecated demangler
	 * @return the new options
	 */
	public GnuDemanglerOptions withDeprecatedDemangler() {
		GnuDemanglerOptions newOptions = new GnuDemanglerOptions(this);
		newOptions.setDemanglerName(GNU_DEMANGLER_V2_24);
		return newOptions;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tdoDisassembly: " + doDisassembly() + ",\n" +
			"\tapplySignature: " + applySignature() + ",\n" +
			"\tdemangleOnlyKnownPatterns: " + demangleOnlyKnownPatterns() + ",\n" +
			"\tdemanglerName: " + demanglerName + ",\n" +
			"\tdemanglerApplicationArguments: " + demanglerApplicationArguments + ",\n" +
		"}";
		//@formatter:on
	}
}
