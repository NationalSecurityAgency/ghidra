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

	private final GnuDemanglerFormat format;
	private final boolean isDeprecated;

	public GnuDemanglerOptions() {
		// use default values
		this(GnuDemanglerFormat.AUTO);
	}

	public GnuDemanglerOptions(GnuDemanglerFormat format) {
		this.format = format;
		// default to the "new" demangler if the format is available in both
		this.isDeprecated = !format.isModernFormat();
	}

	public GnuDemanglerOptions(GnuDemanglerFormat format, boolean isDeprecated) {
		this.format = format;
		this.isDeprecated = isDeprecated;
		if (!format.isAvailable(isDeprecated)) {
			throw new IllegalArgumentException(
				format.name() + " is not available in the "+getDemanglerName());
		}
	}

	public GnuDemanglerOptions(DemanglerOptions copy) {
		super(copy);

		if (copy instanceof GnuDemanglerOptions) {
			GnuDemanglerOptions gCopy = (GnuDemanglerOptions) copy;
			format = gCopy.format;
			isDeprecated = gCopy.isDeprecated;
		} else {
			format = GnuDemanglerFormat.AUTO;
			isDeprecated = false;
		}
	}

	private GnuDemanglerOptions(GnuDemanglerOptions copy, GnuDemanglerFormat format,
			boolean deprecated) {
		super(copy);
		this.format = format;
		this.isDeprecated = deprecated;
	}

	/**
	 * Returns the external demangler executable name to be used for demangling.  The 
	 * default value is {@link #GNU_DEMANGLER_DEFAULT}.
	 * @return the name
	 */
	public String getDemanglerName() {
		return isDeprecated ? GNU_DEMANGLER_V2_24 : GNU_DEMANGLER_V2_33_1;
	}

	/**
	 * A convenience method to copy the state of this options object, changing the 
	 * demangler executable name and demangler format to the specified values.
	 * @param format the demangling format to use
	 * @param isDeprecated true to use the deprecated gnu demangler, else false
	 * @return the new options
	 * @throws IllegalArgumentException if the current format is not available in the
	 * selected demangler.
	 */
	public GnuDemanglerOptions withDemanglerFormat(GnuDemanglerFormat format, boolean isDeprecated)
			throws IllegalArgumentException {
		if (this.format == format && this.isDeprecated == isDeprecated) {
			return this;
		}
		if (format.isAvailable(isDeprecated)) {
			return new GnuDemanglerOptions(this, format, isDeprecated);
		}
		throw new IllegalArgumentException(
			format.name() + " is not available in the "+getDemanglerName());
	}

	/**
	 * Returns the current arguments to be passed to the external demangler executable
	 * @return the arguments
	 */
	public String getDemanglerApplicationArguments() {
		if (format == GnuDemanglerFormat.AUTO) {
			// no format argument
			return "";
		}
		return "-s " + format.getFormat();
	}

	/**
	 * Gets the current demangler format
	 * @return the demangler format
	 */
	public GnuDemanglerFormat getDemanglerFormat() {
		return format;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tdoDisassembly: " + doDisassembly() + ",\n" +
			"\tapplySignature: " + applySignature() + ",\n" +
			"\tdemangleOnlyKnownPatterns: " + demangleOnlyKnownPatterns() + ",\n" +
			"\tdemanglerName: " + getDemanglerName() + ",\n" +
			"\tdemanglerApplicationArguments: " + getDemanglerApplicationArguments() + ",\n" +
		"}";
		//@formatter:on
	}
}
