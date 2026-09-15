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

import generic.json.Json;
import ghidra.app.util.demangler.DemanglerOptions;
import mdemangler.MDOutputOptions;

/**
 * Microsoft demangler options
 */
public class MicrosoftDemanglerOptions extends DemanglerOptions {

	/**
	 * Default Microsoft Demangler option for using the encoded number when outputting an
	 * anonymous namespace node (this can be different from the default option of the underlying
	 * demangler)
	 */
	public static final boolean DEFAULT_MSD_USE_ANON_NS = true;

	/**
	 * Default Microsoft Demangler option for applying user-defined-type (UDT) tags
	 * (e.g., "struct") when the UDT is a template or function argument (this can be different
	 * from the default option of the underlying demangler)
	 */
	public static final boolean DEFAULT_MSD_APPLY_UDT_TAG = false;

	/**
	 * MicrosoftDemanglerOptions that match the default underlying options.  These can be
	 * different than the default MicrosoftDemanglerOptions.
	 */
	public static final MicrosoftDemanglerOptions DEFAULT_UNDERLYING_OUTPUT;
	static {
		DEFAULT_UNDERLYING_OUTPUT = new MicrosoftDemanglerOptions();
		DEFAULT_UNDERLYING_OUTPUT
				.setUseEncodedAnonymousNamespace(MDOutputOptions.DEFAULT_USE_ANON_NS);
		DEFAULT_UNDERLYING_OUTPUT.setApplyUdtArgumentTypeTag(MDOutputOptions.DEFAULT_APPLY_UDT_TAG);
	}

	// Processing options
	private boolean errorOnRemainingChars;
	private MsCInterpretation interpretation;

	// Output options:
	private boolean useEncodedAnonymousNamespace;
	private boolean applyUdtArgumentTypeTag; // specific to MS for now

	/**
	 * Constructor for MicrosoftDemanglerOptions
	 * @param errorOnRemainingCharsArg {@code true} to error on remaining characters
	 */
	public MicrosoftDemanglerOptions(boolean errorOnRemainingCharsArg) {
		this();
		errorOnRemainingChars = errorOnRemainingCharsArg; // override defaultInits()
	}

	/**
	 * Default constructor for MicrosoftDemanglerOptions
	 */
	public MicrosoftDemanglerOptions() {
		super();
		defaultInits();
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
			useEncodedAnonymousNamespace = mCopy.useEncodedAnonymousNamespace;
			applyUdtArgumentTypeTag = mCopy.applyUdtArgumentTypeTag;
		}
		else {
			defaultInits();
		}
	}

	private void defaultInits() {
		errorOnRemainingChars = true;
		interpretation = MsCInterpretation.FUNCTION_IF_EXISTS;
		useEncodedAnonymousNamespace = DEFAULT_MSD_USE_ANON_NS;
		applyUdtArgumentTypeTag = DEFAULT_MSD_APPLY_UDT_TAG;
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

	/**
	 * Sets the output flag to use an anonymous namespace's encoded number to craft a namespace
	 * containing this number instead of using the generic "`anonymous namespace'" name.  Default
	 * is true (to create a namespace containing the encoded number)
	 * @param useEncodedAnonymousNamespaceArg  {@code true} to use
	 */
	public void setUseEncodedAnonymousNamespace(boolean useEncodedAnonymousNamespaceArg) {
		useEncodedAnonymousNamespace = useEncodedAnonymousNamespaceArg;
	}

	/**
	 * Returns {@code true} if the output flag is set to use an anonymous namespace's encoded
	 * number to craft a namespace containing the number instead of using the generic
	 * "`anonymous namespace'" name.
	 * @return {@code true} if encoded number is used to craft a namespace
	 */
	public boolean getUseEncodedAnonymousNamespace() {
		return useEncodedAnonymousNamespace;
	}

	/**
	 * Sets the output flag for applying user-defined tags (e.g., class, struct, union, enum)
	 * within template and function arguments.  Default is {@code true} (to apply)
	 * @param applyUdtArgumentTypeTagArg {@code true} to apply the tags
	 */
	public void setApplyUdtArgumentTypeTag(boolean applyUdtArgumentTypeTagArg) {
		applyUdtArgumentTypeTag = applyUdtArgumentTypeTagArg;
	}

	/**
	 * Returns {@code true} if the output interpretation is set to apply user-defined type
	 * tags (e.g., class, struct, union, enum) within template and function arguments.
	 * @return {@code true} if applying the tags
	 */
	public boolean getApplyUdtArgumentTypeTag() {
		return applyUdtArgumentTypeTag;
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
