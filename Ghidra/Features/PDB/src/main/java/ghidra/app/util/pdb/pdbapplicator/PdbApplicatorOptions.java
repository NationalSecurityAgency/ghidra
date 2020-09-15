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

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;

/**
 * Options used while using a {@link PdbApplicator} to apply a PDB ({@link AbstractPdb}) to a
 * Ghidra program.  These can be optional values used during our development of this PdbApplicator,
 * and thus might not be found in the finished product.
 */
public class PdbApplicatorOptions {

	public static final boolean DEFAULT_APPLY_CODE_SCOPE_BLOCK_COMMENTS = false;
	public static final boolean DEFAULT_APPLY_INSTRUCTION_LABELS = false;
	public static final PdbApplicatorRestrictions DEFAULT_RESTRICTIONS =
		PdbApplicatorRestrictions.NONE;
	public static final boolean DEFAULT_REMAP_ADDRESSES_USING_EXISTING_SYMBOLS = false;
	public static final boolean DEFAULT_ALLOW_DEMOTE_PRIMARY_MANGLED_SYMBOLS = true;

	// TODO: set the following to true if we come up with a reasonably good solution
	public static final boolean DEFAULT_APPLY_FUNCTION_VARIABLES = false;

	public static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
		ObjectOrientedClassLayout.MEMBERS_ONLY;
//	public static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//		ObjectOrientedClassLayout.BASIC_SIMPLE_COMPLEX;
//	public static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//		ObjectOrientedClassLayout.SIMPLE_COMPLEX;
//	public static final ObjectOrientedClassLayout DEFAULT_CLASS_LAYOUT =
//		ObjectOrientedClassLayout.COMPLEX;

	//==============================================================================================
	private boolean applyCodeScopeBlockComments;
	private boolean applyInstructionLabels;
	private PdbApplicatorRestrictions restrictions;
	private boolean remapAddressesUsingExistingPublicSymbols;
	private boolean allowDemotePrimaryMangledSymbols;

	private boolean applyFunctionVariables; // investigation. might produce bad results.

	private ObjectOrientedClassLayout classLayout;

	/**
	 * Constructor
	 */
	public PdbApplicatorOptions() {
		restoreDefaults();
	}

	/**
	 * Set the options back to their default values
	 */
	public void restoreDefaults() {
		applyCodeScopeBlockComments = DEFAULT_APPLY_CODE_SCOPE_BLOCK_COMMENTS;
		applyInstructionLabels = DEFAULT_APPLY_INSTRUCTION_LABELS;
		restrictions = DEFAULT_RESTRICTIONS;
		remapAddressesUsingExistingPublicSymbols = DEFAULT_REMAP_ADDRESSES_USING_EXISTING_SYMBOLS;
		allowDemotePrimaryMangledSymbols = DEFAULT_ALLOW_DEMOTE_PRIMARY_MANGLED_SYMBOLS;
		applyFunctionVariables = DEFAULT_APPLY_FUNCTION_VARIABLES;
		classLayout = DEFAULT_CLASS_LAYOUT;
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

	/**
	 * Set processing restrictions for PdbApplicator
	 * @param restrictions the restrictions
	 */
	public void setRestrictions(PdbApplicatorRestrictions restrictions) {
		this.restrictions = restrictions;
	}

	/**
	 * Returns the current restrictions on PdbApplicator processing
	 * @return the restrictions
	 */
	public PdbApplicatorRestrictions getRestrictions() {
		return restrictions;
	}

	/**
	 * Enable/disable the option to attempt to map addresses using existing mangled symbols
	 * (typically public symbols).
	 * @param enable {@code true} to turn remapAddressesUsingExistingPublicSymbols on
	 */
	public void setRemapAddressUsingExistingPublicSymbols(boolean enable) {
		this.remapAddressesUsingExistingPublicSymbols = enable;
	}

	/**
	 * Returns {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 * @return {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 */
	public boolean remapAddressUsingExistingPublicSymbols() {
		return remapAddressesUsingExistingPublicSymbols;
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
	public void setClassLayout(ObjectOrientedClassLayout classLayout) {
		this.classLayout = classLayout;
	}

	/**
	 * Returns the physical layout out classes.
	 * @return the class layout.
	 */
	public ObjectOrientedClassLayout getClassLayout() {
		return classLayout;
	}

}
