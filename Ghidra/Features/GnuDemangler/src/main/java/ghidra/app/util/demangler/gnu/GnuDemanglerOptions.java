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

	/**
	 * Default constructor to use the modern demangler with auto-detect for the format.  This
	 * constructor will limit demangling to only known symbols.
	 */
	public GnuDemanglerOptions() {
		this(GnuDemanglerFormat.AUTO);
	}

	/**
	 * Constructor to specify a particular format
	 *
	 * @param format signals to use the given format
	 */
	public GnuDemanglerOptions(GnuDemanglerFormat format) {
		this(format, !format.isModernFormat());
	}

	/**
	 * Constructor to specify the format to use and whether to prefer the deprecated format when
	 * both deprecated and modern are available
	 *
	 * @param format the format
	 * @param isDeprecated true if the format is not available in the modern demangler
	 * @throws IllegalArgumentException if the given format is not available in the deprecated
	 *         demangler
	 */
	public GnuDemanglerOptions(GnuDemanglerFormat format, boolean isDeprecated) {
		this.format = format;
		this.isDeprecated = isDeprecated;
		if (!format.isAvailable(isDeprecated)) {
			throw new IllegalArgumentException(
				format.name() + " is not available in the " + getDemanglerName());
		}
	}

	/**
	 * Copy constructor to create a version of this class from a more generic set of options
	 * @param copy the options to copy
	 */
	public GnuDemanglerOptions(DemanglerOptions copy) {
		super(copy);

		if (copy instanceof GnuDemanglerOptions) {
			GnuDemanglerOptions gCopy = (GnuDemanglerOptions) copy;
			format = gCopy.format;
			isDeprecated = gCopy.isDeprecated;
		}
		else {
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
	 * demangler executable name and demangler format to the specified values
	 *
	 * @param demanglerFormat the demangling format to use
	 * @param useDeprecated true to use the deprecated gnu demangler, else false
	 * @return the new options
	 * @throws IllegalArgumentException if the current format is not available in the
	 * selected demangler.
	 */
	public GnuDemanglerOptions withDemanglerFormat(GnuDemanglerFormat demanglerFormat,
			boolean useDeprecated) throws IllegalArgumentException {
		if (this.format == demanglerFormat && this.isDeprecated == useDeprecated) {
			return this;
		}
		if (demanglerFormat.isAvailable(useDeprecated)) {
			return new GnuDemanglerOptions(this, demanglerFormat, useDeprecated);
		}
		throw new IllegalArgumentException(
			demanglerFormat.name() + " is not available in the " + getDemanglerName());
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
