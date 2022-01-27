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
package ghidra.feature.fid.analyzer;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Apply the ApplyFidEntriesCommand to a program.
 *
 */
public class FidAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Function ID";
	private static final String DESCRIPTION = "Finds known functions by hashing.";

	private FidService service;

	// Options
	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an analysis bookmark will be created for each function which was matched " +
			"against one or more known library functions.";
	private static final String APPLY_ALL_FID_LABELS_OPTION_NAME = "Always apply FID labels";
	private static final String APPLY_ALL_FID_LABELS_OPTION_DESCRIPTION = "Enable this option to " +
		"always apply FID labels at functions regardless of existing labels at that function." +
		" When enabled, FID labels will always be added." +
		" When disabled, FID labels will not be applied at functions where " +
		" there already exists a label with type IMPORTED or USER_DEFINED.";

	// Default Option Values
	private static final boolean APPLY_ALL_FID_LABELS_DEFAULT = false;
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	// Option Variables
	private boolean alwaysApplyFidLabels = APPLY_ALL_FID_LABELS_DEFAULT;
	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	private static final String SCORE_THRESHOLD_OPTION_NAME = "Instruction count threshold";
	private static final String SCORE_THRESHOLD_OPTION_DESCRIPTION =
		"The minimum score that a potential match must meet to be labeled by the analyzer. " +
			"Score corresponds roughly to the number of instructions in the function.";
	private float scoreThreshold;

	private static final String MULTIMATCH_THRESHOLD_OPTION_NAME = "Multiple match threshold";
	private static final String MULTIMATCH_THRESHOLD_OPTION_DESCRIPTION =
		"If there are multiple conflicting matches for a function, its score must exceed " +
			"this secondary threshold in order to be labeled by the analyzer";
	private float multiScoreThreshold;

	public FidAnalyzer() {
		/*
		 * FID is listed as a byte analyzer because we don't want to run it all the time.  It
		 * wants to look at as much of the surrounding code (call tree really) as it can, which
		 * means it's expensive.  It can't be running every time a new function is created.
		 *
		 * On the other hand, it's important to identify some types of common functions by their
		 * name...exception handlers for instance, or other non-exiting functions.  So FID should
		 * run as soon as possible after most of the function bodies are discovered.  (FID relies
		 * on proper function bodies existing).
		 */
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		service = new FidService();
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before());
		scoreThreshold = service.getDefaultScoreThreshold();
		multiScoreThreshold = service.getDefaultMultiNameThreshold();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return service.canProcess(program.getLanguage());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return service.canProcess(program.getLanguage());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!service.canProcess(program.getLanguage())) {
			Msg.warn(this, "No FID Libraries apply for language " + program.getLanguageID());
			return false;
		}
		ApplyFidEntriesCommand cmd;
		cmd = new ApplyFidEntriesCommand(set, scoreThreshold, multiScoreThreshold,
			alwaysApplyFidLabels, createBookmarksEnabled);
		cmd.applyTo(program, monitor);

		// Name Change can change the nature of a function from a system
		// library. Probably a better way to do this.
		AutoAnalysisManager.getAnalysisManager(program).functionModifierChanged(
			cmd.getFIDLocations());
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(SCORE_THRESHOLD_OPTION_NAME, service.getDefaultScoreThreshold(),
			null, SCORE_THRESHOLD_OPTION_DESCRIPTION);
		options.registerOption(MULTIMATCH_THRESHOLD_OPTION_NAME,
			service.getDefaultMultiNameThreshold(), null, MULTIMATCH_THRESHOLD_OPTION_DESCRIPTION);
		options.registerOption(APPLY_ALL_FID_LABELS_OPTION_NAME, APPLY_ALL_FID_LABELS_DEFAULT, null,
			APPLY_ALL_FID_LABELS_OPTION_DESCRIPTION);
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		scoreThreshold =
			options.getFloat(SCORE_THRESHOLD_OPTION_NAME, service.getDefaultScoreThreshold());
		multiScoreThreshold = options.getFloat(MULTIMATCH_THRESHOLD_OPTION_NAME,
			service.getDefaultMultiNameThreshold());
		alwaysApplyFidLabels =
			options.getBoolean(APPLY_ALL_FID_LABELS_OPTION_NAME, APPLY_ALL_FID_LABELS_DEFAULT);
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}

}
