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

import java.io.File;
import java.io.IOException;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An analyzer to demangle Swift mangled symbols
 */
public class SwiftDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangler Swift";
	private static final String DESCRIPTION =
		"Demangles Swift symbols and applies appropriate datatype and calling conventions where possible. Requires Swift to be installed.";
	private static final String OPTION_NAME_SWIFT_DIR = "Swift binary directory";
	private static final String OPTION_DESCRIPTION_SWIFT_DIR =
		"Path to the Swift installation binary directory, if not on PATH";

	private static final String OPTION_NAME_INCOMPLETE_PREFIX =
		"Use incomplete demangle label prefix (%s)"
				.formatted(SwiftDemanglerOptions.INCOMPLETE_PREFIX);
	private static final String OPTION_DESCRIPTION_INCOMPLETE_PREFIX =
		"Prefix incomplete demangled labels with '%s'"
				.formatted(SwiftDemanglerOptions.INCOMPLETE_PREFIX);
	private static final String OPTION_NAME_UNSUPPORTED_PREFIX =
		"Use unsupported demangle label prefix (%s)"
				.formatted(SwiftDemanglerOptions.UNSUPPORTED_PREFIX);
	private static final String OPTION_DESCRIPTION_UNSUPPORTED_PREFIX =
		"Prefix unsupported demangled labels with '%s'"
				.formatted(SwiftDemanglerOptions.UNSUPPORTED_PREFIX);

	private File swiftDir;
	private boolean useIncompletePrefix = true;
	private boolean useUnsupportedPrefix = true;
	private SwiftDemangler demangler = new SwiftDemangler();

	/**
	 * Creates a new {@link SwiftDemanglerAnalyzer}
	 */
	public SwiftDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			demangler.initialize(program);
		}
		catch (IOException e) {
			log.appendMsg(e.getMessage());
			return false;
		}
		return super.added(program, set, monitor, log);
	}

	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions options, MessageLog log)
			throws DemangledException {
		return demangler.demangle(mangled, options);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");
		options.registerOption(OPTION_NAME_SWIFT_DIR, OptionType.FILE_TYPE, swiftDir, help,
			OPTION_DESCRIPTION_SWIFT_DIR);
		options.registerOption(OPTION_NAME_INCOMPLETE_PREFIX, OptionType.BOOLEAN_TYPE,
			useIncompletePrefix, help, OPTION_DESCRIPTION_INCOMPLETE_PREFIX);
		options.registerOption(OPTION_NAME_UNSUPPORTED_PREFIX, OptionType.BOOLEAN_TYPE,
			useUnsupportedPrefix, help, OPTION_DESCRIPTION_UNSUPPORTED_PREFIX);
	}

	@Override
	protected boolean validateOptions(DemanglerOptions options, MessageLog log) {
		if (options instanceof SwiftDemanglerOptions swiftDemanglerOptions) {
			try {
				new SwiftNativeDemangler(swiftDemanglerOptions.getSwiftDir());
				return true;
			}
			catch (IOException e) {
				log.appendMsg(e.getMessage());
				log.appendMsg("You must have Swift installed to demangle Swift symbols.\n" +
					"See the \"Demangler Swift\" analyzer options to configure.");
			}
		}
		return false;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		swiftDir = options.getFile(OPTION_NAME_SWIFT_DIR, swiftDir);
		useIncompletePrefix =
			options.getBoolean(OPTION_NAME_INCOMPLETE_PREFIX, useIncompletePrefix);
		useUnsupportedPrefix =
			options.getBoolean(OPTION_NAME_UNSUPPORTED_PREFIX, useUnsupportedPrefix);
	}

	@Override
	protected DemanglerOptions getOptions() {
		SwiftDemanglerOptions swiftDemanglerOptions = new SwiftDemanglerOptions();
		swiftDemanglerOptions.setSwiftDir(swiftDir);
		swiftDemanglerOptions.setIncompletePrefix(useIncompletePrefix);
		swiftDemanglerOptions.setUnsupportedPrefix(useUnsupportedPrefix);
		return swiftDemanglerOptions;
	}
}
