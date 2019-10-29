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
package ghidra.app.util.viewer.field;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.GhidraOptions;
import ghidra.framework.options.*;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

public class BrowserCodeUnitFormatOptions extends CodeUnitFormatOptions
		implements OptionsChangeListener {

	/**
	 * Option for whether to show explicit register variable mark-ups in the operand
	 */
	private final static String REGISTER_VARIABLE_MARKUP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER +
			"Markup Register Variable References";

	/**
	 * Option for whether to show stack variable mark-ups in the operand
	 */
	private final static String STACK_VARIABLE_MARKUP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Markup Stack Variable References";

	/**
	 * Option for whether to include implied stack variable mark-ups in the operand
	 */
	private final static String INFERRED_VARIABLE_MARKUP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER +
			"Markup Inferred Variable References";

	/**
	 * Option for whether to show extended reference mark-ups in the operand.
	 */
	private final static String ALWAYS_SHOW_PRIMARY_REFERENCE_MARKUP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Always Show Primary Reference";

	/**
	 * Option for whether to follow referenced pointers, for read or indirect reference types, 
	 * to show pointer's referenced symbol instead of symbol at pointer.  When applied the 
	 * resulting label will be preceded by -&gt;.
	 */
	private final static String FOLLOW_POINTER_REFERENCE_MARKUP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER +
			"Follow Read or Indirect Pointer References";

	/**
	 * Option for whether to show scalar reference adjustments in the operand.
	 */
	private final static String SCALAR_ADJUSTMENT_OPTION = GhidraOptions.OPERAND_GROUP_TITLE +
		Options.DELIMITER + "Include Scalar Reference Adjustment";

	/**
	 * Option which controls the display of name-space prefixes
	 */
	private final static String NAMESPACE_OPTIONS =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Display Namespace";
	private static final String NAMESPACE_OPTIONS_DESCRIPTIONS =
		"Adjusts the Operands Field namespace display";

	/**
	 * Option which controls the display of data mutability in the mnemonic representation
	 */
	private final static String SHOW_MUTABILITY_OPTION =
		GhidraOptions.MNEMONIC_GROUP_TITLE + Options.DELIMITER + "Show Data Mutability";

	private final static String SHOW_OFFCUT_INFO_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Show Offcut Information";

	private WeakSet<ChangeListener> listeners = WeakDataStructureFactory.createCopyOnReadWeakSet();

	private Options fieldOptions;

	/**
	 * Construct code unit format options for specified field options.
	 * This constructor must be used by the field factory since an OptionsService may
	 * not obtainable at the time they are constructed.
	 * @param fieldOptions field options
	 * @param autoUpdate if true format will auto update if associated options are changed, in 
	 * addition any listeners will be notified when this format is updated.
	 */
	BrowserCodeUnitFormatOptions(ToolOptions fieldOptions, boolean autoUpdate) {
		this.fieldOptions = fieldOptions;
		this.displayOptions = new OptionsBasedDataTypeDisplayOptions(fieldOptions);

		boolean exists = fieldOptions.isRegistered(NAMESPACE_OPTIONS);

		if (!exists) {
			fieldOptions.registerOption(NAMESPACE_OPTIONS, OptionType.CUSTOM_TYPE,
				new NamespaceWrappedOption(), null, NAMESPACE_OPTIONS_DESCRIPTIONS,
				new NamespacePropertyEditor());

			HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Operands_Field");
			fieldOptions.getOptions(GhidraOptions.OPERAND_GROUP_TITLE).setOptionsHelpLocation(hl);

			fieldOptions.registerOption(GhidraOptions.SHOW_BLOCK_NAME_OPTION, false, hl,
				"Prepends memory block names to labels in the operands field.");
			fieldOptions.registerOption(REGISTER_VARIABLE_MARKUP_OPTION, true, hl,
				"Markup function register variable references");
			fieldOptions.registerOption(STACK_VARIABLE_MARKUP_OPTION, true, hl,
				"Markup function stack variable references");
			fieldOptions.registerOption(INFERRED_VARIABLE_MARKUP_OPTION, true, hl,
				"Include INFERRED variable references in markup");
			fieldOptions.registerOption(ALWAYS_SHOW_PRIMARY_REFERENCE_MARKUP_OPTION, true, hl,
				"Forces the primary reference to be rendered with the operand, using the => separator if necessary");
			fieldOptions.registerOption(FOLLOW_POINTER_REFERENCE_MARKUP_OPTION, true, hl,
				"Markup pointer READ/INDIRECT reference with symbol referenced by pointer.  " +
					"An indirectly referenced symbol name will be prefixed with -> .");
			fieldOptions.registerOption(SCALAR_ADJUSTMENT_OPTION, false, hl,
				"Include scalar adjustment of certain reference offsets to maintain replaced scalar value");
			fieldOptions.registerOption(SHOW_MUTABILITY_OPTION, false, hl,
				"Include data mnemonic prefix of 'const' or 'volatile' based upon data setting");
			fieldOptions.registerOption(SHOW_OFFCUT_INFO_OPTION, true, hl,
				"Include trailing offcut address + offset data when showing offcut data");
		}
		updateFormat();

		if (autoUpdate) {
			fieldOptions.addOptionsChangeListener(this);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(GhidraOptions.SHOW_BLOCK_NAME_OPTION) ||
			optionName.equals(REGISTER_VARIABLE_MARKUP_OPTION) ||
			optionName.equals(STACK_VARIABLE_MARKUP_OPTION) ||
			optionName.equals(INFERRED_VARIABLE_MARKUP_OPTION) ||
			optionName.equals(ALWAYS_SHOW_PRIMARY_REFERENCE_MARKUP_OPTION) ||
			optionName.equals(FOLLOW_POINTER_REFERENCE_MARKUP_OPTION) ||
			optionName.equals(SCALAR_ADJUSTMENT_OPTION) || optionName.equals(NAMESPACE_OPTIONS) ||
			optionName.equals(SHOW_MUTABILITY_OPTION) ||
			optionName.equals(SHOW_OFFCUT_INFO_OPTION)) {
			updateFormat();
			notifyListeners();
		}
	}

	private void updateFormat() {
		fieldOptions.registerOption(NAMESPACE_OPTIONS, OptionType.CUSTOM_TYPE,
			new NamespaceWrappedOption(), null, NAMESPACE_OPTIONS_DESCRIPTIONS,
			new NamespacePropertyEditor());
		CustomOption customOption =
			fieldOptions.getCustomOption(NAMESPACE_OPTIONS, new NamespaceWrappedOption());
		if (!(customOption instanceof NamespaceWrappedOption)) {
			throw new AssertException(
				"Someone set an option for " + NAMESPACE_OPTIONS + " that is not the expected " +
					"ghidra.app.util.viewer.field.NamespaceWrappedOption type.");
		}
		NamespaceWrappedOption namespaceOption = (NamespaceWrappedOption) customOption;

		showBlockName = fieldOptions.getBoolean(GhidraOptions.SHOW_BLOCK_NAME_OPTION, false)
				? CodeUnitFormatOptions.ShowBlockName.NON_LOCAL
				: CodeUnitFormatOptions.ShowBlockName.NEVER;

		showNamespace = CodeUnitFormatOptions.ShowNamespace.NEVER;
		localPrefixOverride = null;
		if (namespaceOption.isShowLocalNamespace()) {
			if (namespaceOption.isShowNonLocalNamespace()) {
				showNamespace = CodeUnitFormatOptions.ShowNamespace.ALWAYS;
			}
			else {
				showNamespace = CodeUnitFormatOptions.ShowNamespace.LOCAL;
			}
			if (namespaceOption.isUseLocalPrefixOverride()) {
				localPrefixOverride = namespaceOption.getLocalPrefixText().trim();
				if (localPrefixOverride.length() == 0) {
					localPrefixOverride = null;
				}
			}
		}
		else if (namespaceOption.isShowNonLocalNamespace()) {
			showNamespace = CodeUnitFormatOptions.ShowNamespace.NON_LOCAL;
		}
		showLibraryInNamespace = namespaceOption.isShowLibraryInNamespace();

		doRegVariableMarkup = fieldOptions.getBoolean(REGISTER_VARIABLE_MARKUP_OPTION, true);
		doStackVariableMarkup = fieldOptions.getBoolean(STACK_VARIABLE_MARKUP_OPTION, true);
		includeInferredVariableMarkup =
			fieldOptions.getBoolean(INFERRED_VARIABLE_MARKUP_OPTION, true);
		alwaysShowPrimaryReference =
			fieldOptions.getBoolean(ALWAYS_SHOW_PRIMARY_REFERENCE_MARKUP_OPTION, true);
		followReferencedPointers =
			fieldOptions.getBoolean(FOLLOW_POINTER_REFERENCE_MARKUP_OPTION, true);
		includeScalarReferenceAdjustment = fieldOptions.getBoolean(SCALAR_ADJUSTMENT_OPTION, false);
		showOffcutInfo = fieldOptions.getBoolean(SHOW_OFFCUT_INFO_OPTION, true);
		showDataMutability = fieldOptions.getBoolean(SHOW_MUTABILITY_OPTION, false);
	}

	/**
	 * Add format change listener.
	 * Listeners will only be notified if autoUpdate was true when instantiated.
	 * @param listener the listener
	 */
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	/**
	 * Remove format change listener
	 * @param listener the listener
	 */
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void notifyListeners() {
		final ChangeEvent event = new ChangeEvent(this);
		SwingUtilities.invokeLater(() -> {
			for (ChangeListener listener : listeners) {
				listener.stateChanged(event);
			}
		});
	}

	/**
	 * Get current state of the Follow Referenced Pointers option. 
	 * @return true if operand pointer read of indirect references will be followed and 
	 * non-dynamic pointer referenced symbol will be rendered in place of pointer label. 
	 */
	public boolean followReferencedPointers() {
		return followReferencedPointers;
	}
}
