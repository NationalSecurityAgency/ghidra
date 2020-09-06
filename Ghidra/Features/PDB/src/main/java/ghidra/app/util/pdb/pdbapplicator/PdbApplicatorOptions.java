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

	private static final boolean defaultApplyCodeScopeBlockComments = false;
	private static final boolean defaultApplyInstructionLabels = false;
	private static final boolean defaultApplyDataTypesOnly = false;
	private static final boolean defaultApplyPublicSymbolsOnly = false;
	private static final boolean defaultRemapAddressesUsingExistingPublicSymbols = false;
	private static final boolean defaultAllowDemotePrimaryMangledSymbol = true;

	// TODO: set the following to true if we come up with a reasonably good solution
	private static final boolean defaultApplyFunctionVariables = false;

	private static final CompositeLayoutMode defaultCompositeLayoutMode =
		CompositeLayoutMode.MEMBERS_ONLY;
//	private static final CompositeLayoutMode defaultCompositeLayoutMode =
//		CompositeLayoutMode.BASIC_SIMPLE_COMPLEX;
//	private static final CompositeLayoutMode defaultCompositeLayoutMode =
//		CompositeLayoutMode.SIMPLE_COMPLEX;
//	private static final CompositeLayoutMode defaultCompositeLayoutMode =
//		CompositeLayoutMode.COMPLEX;

	//==============================================================================================
	private boolean applyCodeScopeBlockComments;
	private boolean applyInstructionLabels;
	private boolean applyDataTypesOnly;
	private boolean applyPublicSymbolsOnly;
	private boolean remapAddressesUsingExistingPublicSymbols;
	private boolean allowDemotePrimaryMangledSymbol;

	private boolean applyFunctionVariables; // investigation. might produce bad results.

	private CompositeLayoutMode compositeLayoutMode;

	/**
	 * Constructor
	 */
	public PdbApplicatorOptions() {
		setDefaults();
	}

	/**
	 * Set the options back to their default values
	 */
	public void setDefaults() {
		applyCodeScopeBlockComments = defaultApplyCodeScopeBlockComments;
		applyInstructionLabels = defaultApplyInstructionLabels;
		applyDataTypesOnly = defaultApplyDataTypesOnly;
		applyPublicSymbolsOnly = defaultApplyPublicSymbolsOnly;
		remapAddressesUsingExistingPublicSymbols = defaultRemapAddressesUsingExistingPublicSymbols;
		allowDemotePrimaryMangledSymbol = defaultAllowDemotePrimaryMangledSymbol;
		applyFunctionVariables = defaultApplyFunctionVariables;
		compositeLayoutMode = defaultCompositeLayoutMode;
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
	 * Enable/disable the option to only apply data types (skipping symbol information).
	 * In other words, the default is to apply symbols.
	 * @param applyDataTypesOnly {@code true} to turn applyDataTypesOnly on
	 */
	public void setApplyDataTypesOnly(boolean applyDataTypesOnly) {
		this.applyDataTypesOnly = applyDataTypesOnly;
	}

	/**
	 * Returns {@code true} if applyDataTypesOnly is "on."
	 * @return {@code true} if applyDataTypesOnly is "on."
	 */
	public boolean applyDataTypesOnly() {
		return applyDataTypesOnly;
	}

	/**
	 * Enable/disable the option to only apply public symbols.
	 * @param applyPublicSymbolsOnly {@code true} to turn applyPublicSymbolsOnly on
	 */
	public void setApplyPublicSymbolsOnly(boolean applyPublicSymbolsOnly) {
		this.applyPublicSymbolsOnly = applyPublicSymbolsOnly;
	}

	/**
	 * Returns {@code true} if applyPublicSymbolsOnly is "on."
	 * @return {@code true} if applyPublicSymbolsOnly is "on."
	 */
	public boolean applyPublicSymbolsOnly() {
		return applyPublicSymbolsOnly;
	}

	/**
	 * Enable/disable the option to attempt to map addresses using existing mangled symbols
	 * (typically public symbols).
	 * @param enable {@code true} to turn remapAddressesUsingExistingPublicSymbols on
	 */
	public void setRemapAddressUsingExistingPublicMangledSymbols(boolean enable) {
		this.remapAddressesUsingExistingPublicSymbols = enable;
	}

	/**
	 * Returns {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 * @return {@code true} if remapAddressesUsingExistingPublicSymbols is "on."
	 */
	public boolean remapAddressUsingExistingPublicMangledSymbols() {
		return remapAddressesUsingExistingPublicSymbols;
	}

	/**
	 * Enable/disable the option to allow another symbol be set to primary when the existing
	 * primary symbol is a mangled symbol, regardless of the Symbol SourceType.  This is
	 * typically used when we can get better data type information from the PDB record than
	 * we can from the demangler.
	 * @param enable {@code true} to turn allowDemotePrimaryMangledSymbol on
	 */
	public void setAllowDemotePrimaryMangledSymbol(boolean enable) {
		this.allowDemotePrimaryMangledSymbol = enable;
	}

	/**
	 * Returns {@code true} if allowDemotePrimaryMangledSymbol is "on."
	 * @return {@code true} if allowDemotePrimaryMangledSymbol is "on."
	 */
	public boolean allowDemotePrimaryMangledSymbol() {
		return allowDemotePrimaryMangledSymbol;
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
	 * Set the CompositeLayoutMode.
	 * @param compositeLayoutMode composite layout mode
	 */
	public void setCompositeLayoutMode(CompositeLayoutMode compositeLayoutMode) {
		this.compositeLayoutMode = compositeLayoutMode;
	}

	/**
	 * Returns the mode for physically layout out composites.
	 * @return the layout mode.
	 */
	public CompositeLayoutMode getCompositeLayoutMode() {
		return compositeLayoutMode;
	}

}
