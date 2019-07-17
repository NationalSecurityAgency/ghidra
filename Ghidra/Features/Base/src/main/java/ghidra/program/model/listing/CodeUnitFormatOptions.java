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
package ghidra.program.model.listing;

import ghidra.program.model.data.DataTypeDisplayOptions;

public class CodeUnitFormatOptions {

	/**
	 * <code>ShowBlockName</code> defines the valid options for
	 * controlling the display of block names on labels.
	 */
	public static enum ShowBlockName {
		/**
		 * Indicator to never the show block name in an address, label, or operand
		 * representation.
		 */
		NEVER,
		/**
		 * Indicator to show the block name in all address, label, or operand
		 * representations.
		 */
		ALWAYS,
		/**
		 * Indicator to show the block name in address, label, or operand
		 * representations which are not contained within the current block.
		 */
		NON_LOCAL
	}

	/**
	 * <code>ShowNamespace</code> defines the valid options for
	 * controlling the display of name-spaces on labels.
	 */
	public static enum ShowNamespace {
		/**
		 * Indicator to never the show namespace for a label reference.
		 */
		NEVER,
		/**
		 * Indicator to always show namespace for a label reference..
		 */
		ALWAYS,
		/**
		 * Indicator to show namespace for a label reference if the label is in a 
		 * different namespace from the referenced location.
		 */
		NON_LOCAL,
		/**
		 * Indicator to show namespace for a label reference if the label is in the
		 * same namespace as the reference location (i.e., local to function).
		 */
		LOCAL
	}

	protected volatile ShowBlockName showBlockName = ShowBlockName.NEVER;
	protected volatile ShowNamespace showNamespace = ShowNamespace.NEVER;
	protected volatile String localPrefixOverride = null;
	protected volatile boolean showLibraryInNamespace = true;
	protected volatile boolean doRegVariableMarkup = true;
	protected volatile boolean doStackVariableMarkup = true;
	protected volatile boolean includeInferredVariableMarkup = false;
	protected volatile boolean alwaysShowPrimaryReference = false;
	protected volatile boolean followReferencedPointers = false;
	protected volatile boolean includeScalarReferenceAdjustment = false;
	protected volatile boolean showDataMutability = false;
	protected volatile boolean showOffcutInfo = true;

	protected DataTypeDisplayOptions displayOptions = DataTypeDisplayOptions.DEFAULT;

	public CodeUnitFormatOptions() {
		// use default options;
	}

	/**
	 * Format options constructor using primarily default format options.
	 * @param showBlockName controls display of block name in address representations.
	 * @param showNamespace controls display of namespace path with label references.
	 */
	public CodeUnitFormatOptions(ShowBlockName showBlockName, ShowNamespace showNamespace) {
		this.showBlockName = showBlockName;
		this.showNamespace = showNamespace;
	}

	/**
	 * Format options constructor.  Extended reference mark-up is enabled.
	 * @param showBlockName controls display of block name in address representations.
	 * @param showNamespace controls display of namespace path with label references.
	 * @param localPrefixOverride optional override for local name-space when showNamespace
	 * is ShowNamespace.LOCAL or ShowNamespace.ALWAYS.  Specifying a null value
	 * will cause the actual name-space to be used.
	 * @param doRegVariableMarkup perform register variable/reference mark-up if true
	 * @param doStackVariableMarkup perform stack variable/reference mark-up if true
	 * @param includeInferredVariableMarkup if true and doRegVariableMarkup is also true, an attempt
	 * will be made to mark-up inferred register variable usage.
	 * @param alwaysShowPrimaryReference if true forces the primary reference to be rendered with
	 * the operand using the =&gt; separator if necessary
	 * @param includeScalarReferenceAdjustment if true scalar adjustment of certain reference offsets
	 * will be included to maintain replaced scalar value
	 * @param showLibraryInNamespace if true any referenced external symbols will include 
	 * library name
	 * @param followReferencedPointers if true referenced pointers (read or indirect) will
	 * follow the pointer and display the indirect symbol with -&gt; instead of pointer label.
	 */
	public CodeUnitFormatOptions(ShowBlockName showBlockName, ShowNamespace showNamespace,
			String localPrefixOverride, boolean doRegVariableMarkup, boolean doStackVariableMarkup,
			boolean includeInferredVariableMarkup, boolean alwaysShowPrimaryReference,
			boolean includeScalarReferenceAdjustment, boolean showLibraryInNamespace,
			boolean followReferencedPointers) {
		this.showBlockName = showBlockName;
		this.showNamespace = showNamespace;
		this.showLibraryInNamespace = showLibraryInNamespace;
		this.localPrefixOverride = localPrefixOverride;
		this.doRegVariableMarkup = doRegVariableMarkup;
		this.doStackVariableMarkup = doStackVariableMarkup;
		this.includeInferredVariableMarkup = includeInferredVariableMarkup;
		this.alwaysShowPrimaryReference = alwaysShowPrimaryReference;
		this.followReferencedPointers = followReferencedPointers;
		this.includeScalarReferenceAdjustment = includeScalarReferenceAdjustment;
	}

	/**
	 * Get current ShowBlockName option
	 * @return ShowBlockName option
	 */
	public ShowBlockName getShowBlockNameOption() {
		return showBlockName;
	}
}
