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

import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.sourcelanguage.SourceLanguageID;
import ghidra.app.util.sourcelanguage.SourceLanguageService;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Adds/updates source language-specific support to the program
 */
public class SourceLanguageAnalyzer extends AbstractAnalyzer {

	private final static String NAME = "Source Language Support";
	private final static String DESCRIPTION =
		"Adds/updates source language-specific support to the program";

	private static String OPTION_NAME_SPEC_EXTENSIONS = "Add specification extensions";
	private static String OPTION_DESC_SPEC_EXTENSIONS =
		"Add any source language-specific specification extensions to the program.";
	private static boolean OPTION_DEFAULT_SPEC_EXTENSIONS = true;

	private AtomicBoolean analysisStarted = new AtomicBoolean(false);
	private boolean addSpecExtensions = OPTION_DEFAULT_SPEC_EXTENSIONS;

	/**
	 * Creates a new {@link SourceLanguageAnalyzer}
	 */
	public SourceLanguageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before().before().before().before().before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Enforce that the below code only executes once per analysis session
		if (analysisStarted.getAndSet(true)) {
			return true;
		}

		Set<SourceLanguageID> currentIds = program.getSourceLanguageIDs();
		Set<SourceLanguageID> newIds = SourceLanguageService.find(program, log, monitor);
		program.setSourceLanguageIDs(newIds);

		if (newIds.stream().anyMatch(Predicate.not(currentIds::contains))) {
			log.appendMsg(NAME + "> New source languages were found.\n" +
				"New analyzers may be available if the program is reopened and Auto Analysis is run again.");
		}

		// Optionally add source language spec extensions
		if (addSpecExtensions) {
			if (program.hasExclusiveAccess()) {
				SourceLanguageService.addSpecExtensions(program, newIds, log, monitor);
			}
			else {
				log.appendMsg(
					NAME + "> Cannot add spec extensions without exclusive access to program.");
			}
		}

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_SPEC_EXTENSIONS, OPTION_DEFAULT_SPEC_EXTENSIONS, null,
			OPTION_DESC_SPEC_EXTENSIONS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		addSpecExtensions =
			options.getBoolean(OPTION_NAME_SPEC_EXTENSIONS, OPTION_DEFAULT_SPEC_EXTENSIONS);
	}

	@Override
	public void analysisEnded(Program program) {
		analysisStarted.set(false);
	}
}
