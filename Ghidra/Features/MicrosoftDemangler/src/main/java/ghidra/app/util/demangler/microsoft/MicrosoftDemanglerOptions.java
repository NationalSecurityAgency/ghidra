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

import ghidra.app.util.demangler.DemanglerOptions;

/**
 * Microsoft demangler options
 */
public class MicrosoftDemanglerOptions extends DemanglerOptions {

	private boolean errorOnRemainingChars;
	private MsCInterpretation interpretation;

	/**
	 * Default constructor for MicrosoftDemanglerOptions
	 */
	public MicrosoftDemanglerOptions() {
		this(true);
		interpretation = MsCInterpretation.FUNCTION_IF_EXISTS;
	}

	/**
	 * Constructor for MicrosoftDemanglerOptions
	 * @param errorOnRemainingChars {@code true} to error on remaining characters
	 */
	public MicrosoftDemanglerOptions(boolean errorOnRemainingChars) {
		super();
		this.errorOnRemainingChars = errorOnRemainingChars;
	}

	/**
	 * Copy constructor to create a version of this class from a more generic set of options
	 * @param copy the options to copy
	 */
	public MicrosoftDemanglerOptions(DemanglerOptions copy) {
		super(copy);

		if (copy instanceof MicrosoftDemanglerOptions mCopy) {
			errorOnRemainingChars = mCopy.errorOnRemainingChars;
			interpretation = mCopy.interpretation;
		}
		else {
			errorOnRemainingChars = true;
			interpretation = MsCInterpretation.FUNCTION_IF_EXISTS;
		}
	}

	/**
	 * Sets the control for erroring on remaining characters at demangler completion
	 * @param errorOnRemainingCharsArg {@code true} to error when remaining characters exist
	 */
	public void setErrorOnRemainingChars(boolean errorOnRemainingCharsArg) {
		errorOnRemainingChars = errorOnRemainingCharsArg;
	}

	/**
	 * Returns {@code true} if the process will error when remaining characters exist at the end
	 * of processing
	 * @return {@code true} if will error
	 */
	public boolean errorOnRemainingChars() {
		return errorOnRemainingChars;
	}

	/**
	 * Sets the interpretation for processing a C-style mangled symbol if there could be multiple
	 * interpretations
	 * @param interpretationArg the interpretation to use
	 */
	public void setInterpretation(MsCInterpretation interpretationArg) {
		interpretation = interpretationArg;
	}

	/**
	 * Returns the interpretation for processing a C-style mangled symbol if there could be multiple
	 * interpretations
	 * @return the interpretation used
	 */
	public MsCInterpretation getInterpretation() {
		return interpretation;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tdoDisassembly: " + doDisassembly() + ",\n" +
			"\tapplySignature: " + applySignature() + ",\n" +
			"\terrorOnRemainingChars: " + errorOnRemainingChars + ",\n" +
			"\tinterpretation: " + interpretation + ",\n" +
			"\tdemangleOnlyKnownPatterns: " + demangleOnlyKnownPatterns() + ",\n" +
		"}";
		//@formatter:on
	}
}
