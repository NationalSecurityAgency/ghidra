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
package ghidra.app.plugin.core.analysis;

import java.beans.*;
import java.util.Arrays;

import docking.options.editor.BooleanEditor;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

/**
 * A version of the demangler analyzer to handle GNU GCC symbols
 */
public class GnuDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangler GNU";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	private static final String OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS =
		"Demangle Only Known Mangled Symbols";
	private static final String OPTION_DESCRIPTION_USE_KNOWN_PATTERNS =
		"Only demangle symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.";

	private static final String OPTION_NAME_DEMANGLE_USE_STANDARD_REPLACEMENTS =
		"Use Standard Text Replacements";
	private static final String OPTION_DESCRIPTION_STANDARD_REPLACEMENTS =
		"Use text simplifications in demangled output, for example to use standard c++ typedefs.";

	private static final String OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";

	private static final String OPTION_NAME_APPLY_CALLING_CONVENTION =
		"Apply Function Calling Conventions";
	private static final String OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION =
		"Apply any recovered function signature calling convention";

	static final String OPTION_NAME_USE_DEPRECATED_DEMANGLER = "Use Deprecated Demangler";
	private static final String OPTION_DESCRIPTION_DEPRECATED_DEMANGLER =
		"Signals to use the deprecated demangler when the modern demangler cannot demangle a " +
			"given string";

	static final String OPTION_NAME_DEMANGLER_FORMAT = "Demangler Format";
	private static final String OPTION_DESCRIPTION_DEMANGLER_FORMAT =
		"The demangling format to use";

	private boolean applyFunctionSignature = true;
	private boolean applyCallingConvention = true;
	private boolean demangleOnlyKnownPatterns = false;
	private boolean useStandardReplacements = true;
	private GnuDemanglerFormat demanglerFormat = GnuDemanglerFormat.AUTO;
	private boolean useDeprecatedDemangler = false;

	public GnuDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		demangler = new GnuDemangler();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature, help,
			OPTION_DESCRIPTION_APPLY_SIGNATURE);

		options.registerOption(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention, help,
			OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION);

		options.registerOption(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns,
			help, OPTION_DESCRIPTION_USE_KNOWN_PATTERNS);

		options.registerOption(OPTION_NAME_DEMANGLE_USE_STANDARD_REPLACEMENTS,
			useStandardReplacements, help, OPTION_DESCRIPTION_STANDARD_REPLACEMENTS);

		GnuOptionsEditor optionsEditor = new GnuOptionsEditor();

		options.registerOption(OPTION_NAME_USE_DEPRECATED_DEMANGLER, OptionType.BOOLEAN_TYPE,
			useDeprecatedDemangler, help, OPTION_DESCRIPTION_DEPRECATED_DEMANGLER,
			() -> optionsEditor.getDeprecatedNameEditor());

		options.registerOption(OPTION_NAME_DEMANGLER_FORMAT, OptionType.ENUM_TYPE,
			demanglerFormat, help, OPTION_DESCRIPTION_DEMANGLER_FORMAT,
			() -> optionsEditor.getFormatEditor());

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyFunctionSignature =
			options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature);
		applyCallingConvention =
			options.getBoolean(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention);
		demangleOnlyKnownPatterns =
			options.getBoolean(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns);
		useStandardReplacements =
			options.getBoolean(OPTION_NAME_DEMANGLE_USE_STANDARD_REPLACEMENTS,
				useStandardReplacements);
		demanglerFormat = options.getEnum(OPTION_NAME_DEMANGLER_FORMAT, GnuDemanglerFormat.AUTO);
		useDeprecatedDemangler =
			options.getBoolean(OPTION_NAME_USE_DEPRECATED_DEMANGLER, useDeprecatedDemangler);
	}

	@Override
	protected DemanglerOptions getOptions() {
		GnuDemanglerOptions options =
			new GnuDemanglerOptions(demanglerFormat, useDeprecatedDemangler);
		options.setDoDisassembly(true);
		options.setApplySignature(applyFunctionSignature);
		options.setApplyCallingConvention(applyCallingConvention);
		options.setDemangleOnlyKnownPatterns(demangleOnlyKnownPatterns);
		options.setUseStandardReplacements(useStandardReplacements);
		return options;
	}

	@Override
	protected DemangledObject doDemangle(MangledContext mangledContext, MessageLog log)
			throws DemangledException {
		return demangler.demangle(mangledContext);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	// We only use the editor when not headless, since GUI code in headless will throw an exception.
	// Further, the options below have a relationship, so we need to build them together.
	// The format editor's list of choices presented to the user will change depending on the state
	// of the deprecated boolean editor.
	private class GnuOptionsEditor {

		private BooleanEditor deprecatedEditor;
		private FormatEditor formatEditor;

		private void lazyInit() {
			if (SystemUtilities.isInHeadlessMode()) {
				return; // the editor should not be requested in headless mode
			}

			if (deprecatedEditor != null) {
				return; // already loaded
			}

			deprecatedEditor = new BooleanEditor();
			deprecatedEditor.setValue(Boolean.valueOf(useDeprecatedDemangler));
			formatEditor = new FormatEditor(demanglerFormat, deprecatedEditor);
			deprecatedEditor.addPropertyChangeListener(formatEditor);
		}

		PropertyEditor getDeprecatedNameEditor() {
			lazyInit();
			return deprecatedEditor;
		}

		PropertyEditor getFormatEditor() {
			lazyInit();
			return formatEditor;
		}
	}

	private static class FormatEditor extends EnumEditor implements PropertyChangeListener {

		private final FormatSelector selector;
		private final BooleanEditor isDeprecated;

		FormatEditor(GnuDemanglerFormat value, BooleanEditor isDeprecated) {
			setValue(value);
			this.isDeprecated = isDeprecated;
			this.selector = new FormatSelector(this);
		}

		@Override
		public boolean supportsCustomEditor() {
			return true;
		}

		@Override
		public FormatSelector getCustomEditor() {
			return selector;
		}

		@Override
		public GnuDemanglerFormat[] getEnums() {
			return Arrays.stream(GnuDemanglerFormat.values())
					.filter(this::filter)
					.toArray(GnuDemanglerFormat[]::new);
		}

		@Override
		public String[] getTags() {
			return Arrays.stream(GnuDemanglerFormat.values())
					.filter(this::filter)
					.map(GnuDemanglerFormat::name)
					.toArray(String[]::new);
		}

		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			GnuDemanglerFormat format = selector.getFormat();
			selector.reset(getTags());
			if (format.isAvailable(isDeprecatedDemangler())) {
				setValue(format);
				selector.setFormat(format);
			}
			else {
				setValue(GnuDemanglerFormat.AUTO);
			}
		}

		private boolean isDeprecatedDemangler() {
			return (Boolean) isDeprecated.getValue();
		}

		private boolean filter(GnuDemanglerFormat f) {
			return f.isAvailable(isDeprecatedDemangler());
		}
	}

	private static class FormatSelector extends PropertySelector {

		public FormatSelector(FormatEditor fe) {
			super(fe);
		}

		void reset(String[] tags) {
			removeAllItems();
			for (String tag : tags) {
				addItem(tag);
			}
		}

		GnuDemanglerFormat getFormat() {
			return GnuDemanglerFormat.valueOf((String) getSelectedItem());
		}

		void setFormat(GnuDemanglerFormat format) {
			setSelectedItem(format.name());
		}
	}
}
