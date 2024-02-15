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
package ghidra.app.plugin.core.analysis.rust;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.Arrays;

import docking.options.editor.BooleanEditor;
import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.plugin.core.analysis.rust.demangler.*;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.demangler.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * A version of the demangler analyzer to handle Rust symbols
 */
public class RustDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangler Rust";
	private static final String DESCRIPTION = "Attempt to demangle any symbols mangled by rustc.";

	private static final String OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS =
		"Demangle Only Known Mangled Symbols";
	private static final String OPTION_DESCRIPTION_USE_KNOWN_PATTERNS =
		"Only demangle symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.";

	private static final String OPTION_NAME_APPLY_CALLING_CONVENTION =
		"Apply Function Calling Conventions";
	private static final String OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION =
		"Apply any recovered function signature calling convention";

	static final String OPTION_NAME_USE_DEPRECATED_DEMANGLER = "Use Deprecated Demangler";
	private static final String OPTION_DESCRIPTION_DEPRECATED_DEMANGLER =
		"Use the deprecated demangler when the modern demangler cannot demangle a " +
			"given string";

	static final String OPTION_NAME_DEMANGLER_FORMAT = "Demangler Format";
	private static final String OPTION_DESCRIPTION_DEMANGLER_FORMAT =
		"The demangling format to use";

	private boolean applyCallingConvention = true;
	private boolean demangleOnlyKnownPatterns = true;
	private RustDemanglerFormat demanglerFormat = RustDemanglerFormat.AUTO;
	private boolean useDeprecatedDemangler = false;

	private RustDemangler demangler = new RustDemangler();

	public RustDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		// Set priority to one before the default AbstractDemanglerAnalyzer priority
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");

		options.registerOption(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention, help,
			OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION);

		options.registerOption(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns,
			help, OPTION_DESCRIPTION_USE_KNOWN_PATTERNS);

		BooleanEditor deprecatedEditor = null;
		FormatEditor formatEditor = null;
		if (!SystemUtilities.isInHeadlessMode()) {
			// Only add the custom options editor when not headless.   The custom editor allows
			// the list of choices presented to the user to change depending on the state of the
			// useDeprecatedDemangler flag.
			deprecatedEditor = new BooleanEditor();
			deprecatedEditor.setValue(Boolean.valueOf(useDeprecatedDemangler));
			formatEditor = new FormatEditor(demanglerFormat, deprecatedEditor);
			deprecatedEditor.addPropertyChangeListener(formatEditor);
		}

		options.registerOption(OPTION_NAME_USE_DEPRECATED_DEMANGLER, OptionType.BOOLEAN_TYPE,
			useDeprecatedDemangler, help, OPTION_DESCRIPTION_DEPRECATED_DEMANGLER,
			deprecatedEditor);

		options.registerOption(OPTION_NAME_DEMANGLER_FORMAT, OptionType.ENUM_TYPE, demanglerFormat,
			help, OPTION_DESCRIPTION_DEMANGLER_FORMAT, formatEditor);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyCallingConvention =
			options.getBoolean(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention);
		demangleOnlyKnownPatterns =
			options.getBoolean(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns);
		demanglerFormat = options.getEnum(OPTION_NAME_DEMANGLER_FORMAT, RustDemanglerFormat.AUTO);
		useDeprecatedDemangler =
			options.getBoolean(OPTION_NAME_USE_DEPRECATED_DEMANGLER, useDeprecatedDemangler);
	}

	@Override
	protected DemanglerOptions getOptions() {
		RustDemanglerOptions options =
			new RustDemanglerOptions(demanglerFormat, useDeprecatedDemangler);
		options.setDoDisassembly(true);
		options.setApplyCallingConvention(applyCallingConvention);
		options.setDemangleOnlyKnownPatterns(demangleOnlyKnownPatterns);
		return options;
	}

	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions demanglerOptions,
			MessageLog log) throws DemangledException {
		return demangler.demangle(mangled, demanglerOptions);
	}

	@Override
	protected void apply(Program program, Address address, DemangledObject demangled,
			DemanglerOptions options, MessageLog log, TaskMonitor monitor) {
		try {
			if (demangled instanceof DemangledFunction defunc) {
				defunc.applyTo(program, address, options, monitor);
			}
		}
		catch (Exception e) {
			// Failed to apply demangled function
		}

		// Apply it as a variable instead of as a function

		String mangled = demangled.getMangledString();
		String original = demangled.getOriginalDemangled();
		String name = demangled.getName();
		Demangled namespace = demangled.getNamespace();

		DemangledVariable demangledVariable = new DemangledVariable(mangled, original, name);
		demangledVariable.setNamespace(namespace);

		super.apply(program, address, demangledVariable, options, log, monitor);
	}

	private static class FormatEditor extends EnumEditor implements PropertyChangeListener {

		private final FormatSelector selector;
		private final BooleanEditor isDeprecated;

		FormatEditor(RustDemanglerFormat value, BooleanEditor isDeprecated) {
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
		public RustDemanglerFormat[] getEnums() {
			return Arrays.stream(RustDemanglerFormat.values())
					.filter(this::filter)
					.toArray(RustDemanglerFormat[]::new);
		}

		@Override
		public String[] getTags() {
			return Arrays.stream(RustDemanglerFormat.values())
					.filter(this::filter)
					.map(RustDemanglerFormat::name)
					.toArray(String[]::new);
		}

		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			RustDemanglerFormat format = selector.getFormat();
			selector.reset(getTags());
			if (format.isAvailable(isDeprecatedDemangler())) {
				setValue(format);
				selector.setFormat(format);
			}
			else {
				setValue(RustDemanglerFormat.AUTO);
			}
		}

		private boolean isDeprecatedDemangler() {
			return (Boolean) isDeprecated.getValue();
		}

		private boolean filter(RustDemanglerFormat f) {
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

		RustDemanglerFormat getFormat() {
			return RustDemanglerFormat.valueOf((String) getSelectedItem());
		}

		void setFormat(RustDemanglerFormat format) {
			setSelectedItem(format.name());
		}
	}
}
