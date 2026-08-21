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

import ghidra.app.util.demangler.DemanglerOptions;

/**
 * Rust demangler options
 */
public class RustDemanglerOptions extends DemanglerOptions {

	private final RustDemanglerFormat format;
	private final boolean isDeprecated;

	/**
	 * Default constructor to use the modern demangler with auto-detect for the format.  This
	 * constructor will limit demangling to only known symbols.
	 */
	public RustDemanglerOptions() {
		this(RustDemanglerFormat.AUTO);
	}

	/**
	 * Constructor to specify a particular format
	 *
	 * @param format signals to use the given format
	 */
	public RustDemanglerOptions(RustDemanglerFormat format) {
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
	public RustDemanglerOptions(RustDemanglerFormat format, boolean isDeprecated) {
		this.format = format;
		this.isDeprecated = isDeprecated;
		if (!format.isAvailable(isDeprecated)) {
			throw new IllegalArgumentException(format.name() + " is not available");
		}
	}

	/**
	 * Copy constructor to create a version of this class from a more generic set of options
	 * @param copy the options to copy
	 */
	public RustDemanglerOptions(DemanglerOptions copy) {
		super(copy);

		if (copy instanceof RustDemanglerOptions) {
			RustDemanglerOptions gCopy = (RustDemanglerOptions) copy;
			format = gCopy.format;
			isDeprecated = gCopy.isDeprecated;
		}
		else {
			format = RustDemanglerFormat.AUTO;
			isDeprecated = false;
		}
	}

	/**
	 * Gets the current demangler format
	 * @return the demangler format
	 */
	public RustDemanglerFormat getDemanglerFormat() {
		return format;
	}

	@Override
	public String toString() {
		//@formatter:off
                return "{\n" +
                        "\tdoDisassembly: " + doDisassembly() + ",\n" +
                        "\tapplySignature: " + applySignature() + ",\n" +
                        "\tdemangleOnlyKnownPatterns: " + demangleOnlyKnownPatterns() + ",\n" +
                "}";
                //@formatter:on
	}
}
