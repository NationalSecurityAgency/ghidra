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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.framework.options.Options;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * Options used while using a {@link DefaultPdbApplicator} to apply a PDB ({@link AbstractPdb}) to a
 * Ghidra program.  These can be optional values used during our development of this PdbApplicator,
 * and thus might not be found in the finished product.
 */
public class PdbApplicatorOptions {

	// Developer turn on/off options that are in still in development. See launch.properties.
	private static final boolean DEVELOPER_MODE = Boolean.getBoolean("ghidra.pdb.developerMode");

	// Applicator Control.
	private static final String OPTION_NAME_PROCESSING_CONTROL = "Control";
	private static final String OPTION_DESCRIPTION_PROCESSING_CONTROL =
		"Applicator processing control.";
	private static final PdbApplicatorControl DEFAULT_CONTROL = PdbApplicatorControl.ALL;
	private PdbApplicatorControl control;

	// Apply Code Block Comments.
	private static final String OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS =
		"Apply Code Scope Block Comments";
	private static final String OPTION_DESCRIPTION_APPLY_CODE_SCOPE_BLOCK_COMMENTS =
		"If checked, pre/post-comments will be applied when code scope blocks are specified.";
	private static final boolean DEFAULT_APPLY_CODE_SCOPE_BLOCK_COMMENTS = false;
	private boolean applyCodeScopeBlockComments;

	// Apply Instruction Labels information.
	// Mechanism to apply instruction labels is not yet implemented-> does nothing
	private static final String OPTION_NAME_APPLY_INSTRUCTION_LABELS = "Apply Instruction Labels";
	private static final String OPTION_DESCRIPTION_APPLY_INSTRUCTION_LABELS =
		"If checked, labels associated with instructions will be applied.";
	private static final boolean DEFAULT_APPLY_INSTRUCTION_LABELS = false;
	private boolean applyInstructionLabels;
	// If the above option is enabled, allowing instruction labels to be applied, this
	// edit box provides a filter to prevent any labels matching this pattern from being
	// applied to the program.
	private static final String OPTION_NAME_EXCLUDE_INSTRUCTION_LABELS =
		"Exclude Instruction Labels";
	private static final String OPTION_DESCRIPTION_EXCLUDE_INSTRUCTION_LABELS =
		"Regular expression describing instruction labels to be excluded when \"" +
			OPTION_NAME_APPLY_INSTRUCTION_LABELS + "\" is enabled.";
	private static final String DEFAULT_EXCLUDE_INSTRUCTION_LABELS = "$a"; // "$a" will never match
	private Pattern DEFAULT_EXCLUDE_INSTRUCTION_LABELS_PATTERN;
	{
		try {
			DEFAULT_EXCLUDE_INSTRUCTION_LABELS_PATTERN =
				Pattern.compile(DEFAULT_EXCLUDE_INSTRUCTION_LABELS);
		}
		catch (PatternSyntaxException e) {
			throw new AssertException(
				"Programming error: invalid default exclude labels pattern");
		}
	}

	private String excludeInstructionLabels;
	private Pattern excludeInstructionLabelsPattern;

	// Attempt to map address using existing mangled symbols.
	private static final String OPTION_NAME_ADDRESS_REMAP = "Address Remap Using Existing Symbols";
	private static final String OPTION_DESCRIPTION_ADDRESS_REMAP =
		"If checked, attempts to remap address to those matching existing public symbols.";
	private static final boolean DEFAULT_REMAP_ADDRESSES_USING_EXISTING_SYMBOLS = false;
	private boolean remapAddressUsingExistingPublicMangledSymbols;

	// Allow a mangled symbol to be demoted from being a primary symbol if another symbol and
	//  associated explicit data type will be laid down at the location.  This option exists
	//  because we expect the PDB explicit data type will be more accurate than trying to
	//  have the demangler lay down the data type.
	private static final String OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY =
		"Allow demote mangled symbol from primary";
	private static final String OPTION_DESCRIPTION_ALLOW_DEMOTE_MANGLED_PRIMARY =
		"If checked, allows a mangled symbol to be demoted from primary if a possibly " +
			"better data type can be laid down with a nonmangled symbol.";
	private static final boolean DEFAULT_ALLOW_DEMOTE_PRIMARY_MANGLED_SYMBOLS = true;
	private boolean allowDemotePrimaryMangledSymbols;

	// Apply Function Variables
	// Investigation. might produce bad results.
	private static final String OPTION_NAME_APPLY_FUNCTION_VARIABLES = "Apply Function Variables";
	private static final String OPTION_DESCRIPTION_APPLY_FUNCTION_VARIABLES =
		"If checked, attempts to apply function parameters and local variables for program functions.";
	// TODO: set the following to true if we come up with a reasonably good solution
	private static final boolean DEFAULT_APPLY_FUNCTION_VARIABLES = false;
	private boolean applyFunctionVariables;

	// Sets the composite layout.
	// Legacy
	//   - similar to existing DIA-based PDB Analyzer, only placing current composite direct
	//     members (none from parent classes.
	// Warning: the remaining experimental layout choices may not be kept and are not guaranteed
	//          to result in data types that will be compatible with future Ghidra releases:
	// Complex with Basic Fallback
	//   - Performs Complex layout, but if the current class has no parent classes, it will not
	//     encapsulate the current class's 'direct' members.
	// Simple
	//   - Performs Complex layout, except in rare instances where , so in most cases is the same
	//     as 'Complex with Basic Fallback' layout.
	// Complex
	//   - Puts all current class members and 'direct' parents' 'direct' components into an
	//     encapsulating 'direct' container
	private static final String OPTION_NAME_COMPOSITE_LAYOUT = "Composite Layout Choice";
	private static final String OPTION_DESCRIPTION_COMPOSITE_LAYOUT =
		"Legacy layout like original PDB Analyzer. Warning: other choices have no compatibility" +
			" guarantee with future Ghidra releases or minor PDB Analyzer changes";
	private static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
		ObjectOrientedClassLayout.MEMBERS_ONLY;
	private ObjectOrientedClassLayout compositeLayout;
//	private static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//	ObjectOrientedClassLayout.BASIC_SIMPLE_COMPLEX;
//private static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//	ObjectOrientedClassLayout.SIMPLE_COMPLEX;
//private static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//	ObjectOrientedClassLayout.COMPLEX;

	//==============================================================================================

	/**
	 * Constructor
	 */
	public PdbApplicatorOptions() {
		setDefaults();
	}

	/**
	 * Register the PdbApplicatorOptions for "Analysis."
	 * @param options the Options that will have PdbApplicator options registered in.
	 */
	public void registerAnalyzerOptions(Options options) {
		registerOptions(options, false);
	}

	/**
	 * Load the PdbApplicatorOptions for used for "Analysis."
	 * @param options the Options that have PdbApplicator options registered in.
	 */
	public void loadAnalyzerOptions(Options options) {
		loadOptions(options, false);
	}

	/**
	 * Register the PdbApplicatorOptions for "Load PDB."
	 * @param options the Options that will have PdbApplicator options registered in.
	 */
	public void registerLoaderOptions(Options options) {
		registerOptions(options, true);
	}

	/**
	 * Load the PdbApplicatorOptions for used for "Load PDB."
	 * @param options the Options that have PdbApplicator options registered in.
	 */
	public void loadLoaderOptions(Options options) {
		loadOptions(options, true);
	}

	private void registerOptions(Options options, boolean enableControl) {
		HelpLocation help = null;

		if (DEVELOPER_MODE || enableControl) {
			options.registerOption(OPTION_NAME_PROCESSING_CONTROL, PdbApplicatorControl.ALL, help,
				OPTION_DESCRIPTION_PROCESSING_CONTROL);
		}

		// PdbApplicatorOptions
		if (DEVELOPER_MODE) {

			options.registerOption(OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS,
				applyCodeScopeBlockComments, help,
				OPTION_DESCRIPTION_APPLY_CODE_SCOPE_BLOCK_COMMENTS);

			// Mechanism to apply instruction labels is not yet implemented-> does nothing
			options.registerOption(OPTION_NAME_APPLY_INSTRUCTION_LABELS, applyInstructionLabels,
				help, OPTION_DESCRIPTION_APPLY_INSTRUCTION_LABELS);

			// If the above option is enabled, allowing instruction labels to be applied, this
			// edit box provides a filter to prevent any labels matching this pattern from being
			// applied to the program.
			options.registerOption(OPTION_NAME_EXCLUDE_INSTRUCTION_LABELS, excludeInstructionLabels,
				help, OPTION_DESCRIPTION_EXCLUDE_INSTRUCTION_LABELS);
			validatePattern(options);
			// Can we disable this one above based upon the one above it?  Do it with custom editor.

			// The remap capability is not completely implemented... do not turn on.
			options.registerOption(OPTION_NAME_ADDRESS_REMAP,
				remapAddressUsingExistingPublicMangledSymbols, help,
				OPTION_DESCRIPTION_ADDRESS_REMAP);

			options.registerOption(OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY,
				allowDemotePrimaryMangledSymbols, help,
				OPTION_DESCRIPTION_ALLOW_DEMOTE_MANGLED_PRIMARY);

			// Function params and local implementation is not complete... do not turn on.
			options.registerOption(OPTION_NAME_APPLY_FUNCTION_VARIABLES, applyFunctionVariables,
				help, OPTION_DESCRIPTION_APPLY_FUNCTION_VARIABLES);

			// Object-oriented composite layout is fairly far along, but its use will likely not
			// be forward compatible with future Ghidra work in this area; i.e., it might leave
			// the data type manager in a bad state for future revisions.  While the current
			// layout mechanism might work, I will likely change it to, instead, create a
			// syntactic intermediate representation before creating the final layout.  This will
			// aid portability between tool chains and versions and yield a standard way of
			// data-basing and presenting the information to a user.
			options.registerOption(OPTION_NAME_COMPOSITE_LAYOUT, compositeLayout, help,
				OPTION_DESCRIPTION_COMPOSITE_LAYOUT);
		}
	}

	private void loadOptions(Options options, boolean enableControl) {

		if (DEVELOPER_MODE || enableControl) {
			control = options.getEnum(OPTION_NAME_PROCESSING_CONTROL, PdbApplicatorControl.ALL);
		}

		// PdbApplicatorOptions
		if (DEVELOPER_MODE) {

			applyCodeScopeBlockComments = options.getBoolean(
				OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS, applyCodeScopeBlockComments);

			// Mechanism to apply instruction labels
			applyInstructionLabels =
				options.getBoolean(OPTION_NAME_APPLY_INSTRUCTION_LABELS, applyInstructionLabels);

			// If the above option is enabled, allowing instruction labels to be applied, this
			// edit box provides a filter to prevent any labels matching this pattern from being
			// applied to the program
			excludeInstructionLabels =
				options.getString(OPTION_NAME_EXCLUDE_INSTRUCTION_LABELS, excludeInstructionLabels);
			validatePattern(options);

			remapAddressUsingExistingPublicMangledSymbols = options.getBoolean(
				OPTION_NAME_ADDRESS_REMAP, remapAddressUsingExistingPublicMangledSymbols);

			allowDemotePrimaryMangledSymbols = options.getBoolean(
				OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY, allowDemotePrimaryMangledSymbols);

			applyFunctionVariables =
				options.getBoolean(OPTION_NAME_APPLY_FUNCTION_VARIABLES, applyFunctionVariables);

			compositeLayout = options.getEnum(OPTION_NAME_COMPOSITE_LAYOUT, compositeLayout);
		}
	}

	// The following code cannot remain in a final solution... The options editor does
	// not get an updated String written to it.  Ultimately, there is no way to validate
	// this value other than have a custom options editor, which is the direction we
	// already believe we need to take for purposes of appropriately grouping options
	// (other than in an alphabetical order).
	private void validatePattern(Options options) {
		try {
			excludeInstructionLabelsPattern = Pattern.compile(excludeInstructionLabels);
		}
		catch (PatternSyntaxException e) {
			Msg.error(this, "Invalid " + OPTION_NAME_EXCLUDE_INSTRUCTION_LABELS + " value: " +
				excludeInstructionLabels + "\n  Resetting to default value.");
			excludeInstructionLabels = DEFAULT_EXCLUDE_INSTRUCTION_LABELS;
			excludeInstructionLabelsPattern = DEFAULT_EXCLUDE_INSTRUCTION_LABELS_PATTERN;
			options.restoreDefaultValue(OPTION_NAME_EXCLUDE_INSTRUCTION_LABELS);
		}
	}

	/**
	 * Set the options to their default values
	 */
	public void setDefaults() {
		applyCodeScopeBlockComments = DEFAULT_APPLY_CODE_SCOPE_BLOCK_COMMENTS;
		applyInstructionLabels = DEFAULT_APPLY_INSTRUCTION_LABELS;
		excludeInstructionLabels = DEFAULT_EXCLUDE_INSTRUCTION_LABELS;
		excludeInstructionLabelsPattern = DEFAULT_EXCLUDE_INSTRUCTION_LABELS_PATTERN;
		control = DEFAULT_CONTROL;
		remapAddressUsingExistingPublicMangledSymbols =
			DEFAULT_REMAP_ADDRESSES_USING_EXISTING_SYMBOLS;
		allowDemotePrimaryMangledSymbols = DEFAULT_ALLOW_DEMOTE_PRIMARY_MANGLED_SYMBOLS;
		applyFunctionVariables = DEFAULT_APPLY_FUNCTION_VARIABLES;
		compositeLayout = DEFAULT_CLASS_LAYOUT;
	}

	/**
	 * Enable/disable developmental debug.
	 * @param applyCodeScopeBlockComments {@code true} to turn applyCodeScopeBlockComments on
	 */
	public void setApplyCodeScopeBlockComments(boolean applyCodeScopeBlockComments) {
		this.applyCodeScopeBlockComments = applyCodeScopeBlockComments;
	}

	/**
	 * Returns {@code true} if applyCodeScopeBlockComments is "on."
	 * @return {@code true} if applyCodeScopeBlockComments is "on."
	 */
	public boolean applyCodeScopeBlockComments() {
		return applyCodeScopeBlockComments;
	}

	/**
	 * Enable/disable developmental debug.
	 * @param applyInstructionLabels {@code true} to turn applyInstructionLabels on
	 */
	public void setApplyInstructionLabels(boolean applyInstructionLabels) {
		this.applyInstructionLabels = applyInstructionLabels;
	}

	/**
	 * Returns {@code true} if applyInstructionLabels is "on."
	 * @return {@code true} if applyInstructionLabels is "on."
	 */
	public boolean applyInstructionLabels() {
		return applyInstructionLabels;
	}

	// If the above option is enabled, allowing instruction labels to be applied, this
	// edit box provides a filter to prevent any labels matching this pattern from being
	// applied to the program
	/**
	 * Set regular expression string describing labels to exclude from application.
	 * @param excludeInstructionLabels regular expression describing instruction labels to exclude
	 */
	public void setApplyInstructionLabels(String excludeInstructionLabels) {
		this.excludeInstructionLabels = excludeInstructionLabels;
	}

	/**
	 * Returns the string containing the regular expression describing instruction labels being
	 * excluded from application.  Applicable when {@code applyInstructionLabels} is enabled
	 * @return the regular expression String
	 */
	public String excludeInstructionLabels() {
		return excludeInstructionLabels;
	}

	/**
	 * Returns the Regex Pattern for the Exclude Instruction Labels field.
	 * @return the Pattern.
	 */
	public Pattern excludeInstructionLabelsPattern() {
		return excludeInstructionLabelsPattern;
	}

	/**
	 * Set processing control for PdbApplicator
	 * @param control the processing control
	 */
	public void setProcessingControl(PdbApplicatorControl control) {
		this.control = control;
	}

	/**
	 * Returns the current processing control for the PdbApplicator
	 * @return the processing control
	 */
	public PdbApplicatorControl getProcessingControl() {
		return control;
	}

	/**
	 * Enable/disable the option to attempt to map addresses using existing mangled symbols
	 * (typically public symbols).
	 * @param enable {@code true} to turn remapAddressesUsingExistingPublicSymbols on
	 */
	public void setRemapAddressUsingExistingPublicSymbols(boolean enable) {
		this.remapAddressUsingExistingPublicMangledSymbols = enable;
	}

	/**
	 * Returns {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 * @return {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 */
	public boolean remapAddressUsingExistingPublicSymbols() {
		return remapAddressUsingExistingPublicMangledSymbols;
	}

	/**
	 * Enable/disable the option to allow another symbol be set to primary when the existing
	 * primary symbol is a mangled symbol, regardless of the Symbol SourceType.  This is
	 * typically used when we can get better data type information from the PDB record than
	 * we can from the demangler.
	 * @param enable {@code true} to turn allowDemotePrimaryMangledSymbols on
	 */
	public void setAllowDemotePrimaryMangledSymbols(boolean enable) {
		this.allowDemotePrimaryMangledSymbols = enable;
	}

	/**
	 * Returns {@code true} if allowDemotePrimaryMangledSymbols is "on."
	 * @return {@code true} if allowDemotePrimaryMangledSymbols is "on."
	 */
	public boolean allowDemotePrimaryMangledSymbols() {
		return allowDemotePrimaryMangledSymbols;
	}

	/**
	 * Enable/disable the option to apply function params and locals, which might produce improper
	 * results.
	 * @param applyFunctionVariables {@code true} to turn applyPublicSymbolsOnly on
	 */
	public void setApplyFunctionVariables(boolean applyFunctionVariables) {
		this.applyFunctionVariables = applyFunctionVariables;
	}

	/**
	 * Returns {@code true} if applyFunctionVariables is "on."
	 * @return {@code true} if applyFunctionVariables is "on."
	 */
	public boolean applyFunctionVariables() {
		return applyFunctionVariables;
	}

	/**
	 * Set the class layout.
	 * @param classLayout composite layout
	 */
	public void setCompositeLayout(ObjectOrientedClassLayout classLayout) {
		this.compositeLayout = classLayout;
	}

	/**
	 * Returns the physical layout out classes.
	 * @return the class layout.
	 */
	public ObjectOrientedClassLayout getCompositeLayout() {
		return compositeLayout;
	}
}
