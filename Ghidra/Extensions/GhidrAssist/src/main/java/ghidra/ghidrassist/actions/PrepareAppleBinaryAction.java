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
package ghidra.ghidrassist.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.ghidrassist.GhidrAssistPlugin;
import ghidra.ghidrassist.apple.AppleBinaryContext;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * One-click "prepare Apple binary" convenience: enables the Objective-C and
 * Swift analyzers on the current program and schedules a re-analysis. This
 * does NOT add any new decompilation capability — Ghidra already decompiles
 * Mach-O / AArch64 Apple Silicon / x86_64 Mach-O / dyld-cache images with
 * the loaders and processors shipped under {@code Ghidra/Processors/AARCH64}
 * and {@code Ghidra/Features/Base}. This action just toggles on the analyzers
 * that are off by default on non-Apple binaries and that materially improve
 * decompiler output for Mach-O.
 */
public class PrepareAppleBinaryAction extends DockingAction {

	private static final String OBJC_MESSAGE_ANALYZER = "Objective-C Message Analyzer";
	private static final String OBJC_METADATA_ANALYZER = "Objective-C Type Metadata Analyzer";
	private static final String SWIFT_METADATA_ANALYZER = "Swift Type Metadata Analyzer";

	private final GhidrAssistPlugin plugin;

	public PrepareAppleBinaryAction(GhidrAssistPlugin plugin) {
		super("GhidrAssist Prepare Apple Binary", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(
			new MenuData(new String[] { "Tools", "GhidrAssist", "Prepare Apple Binary…" },
				null, "GhidrAssist"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Program program = plugin.getCurrentProgram();
		return program != null && AppleBinaryContext.from(program).isMachO();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			return;
		}
		AppleBinaryContext ctx = AppleBinaryContext.from(program);
		if (!ctx.isMachO()) {
			Msg.showInfo(this, null, "GhidrAssist",
				"The current program is not Mach-O (" + ctx.summary() + ").\n" +
					"This action only applies to macOS / iOS / Apple Silicon binaries.");
			return;
		}

		String preview = ""
			+ "Enable the following analyzers on this program and schedule re-analysis?\n\n"
			+ "  • " + OBJC_MESSAGE_ANALYZER + "\n"
			+ "  • " + OBJC_METADATA_ANALYZER + "\n"
			+ "  • " + SWIFT_METADATA_ANALYZER + "\n\n"
			+ "Detected: " + ctx.summary() + ".\n\n"
			+ "These analyzers already ship with Ghidra; this action just toggles them on\n"
			+ "and re-runs analysis. It does not add new decompilation capability.";
		int choice =
			OptionDialog.showYesNoDialog(null, "GhidrAssist — Prepare Apple Binary", preview);
		if (choice != OptionDialog.YES_OPTION) {
			return;
		}

		TaskLauncher.launch(new Task("GhidrAssist: Prepare Apple binary", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				int tx = program.startTransaction("GhidrAssist: enable Apple analyzers");
				boolean commit = false;
				try {
					Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
					options.setBoolean(OBJC_MESSAGE_ANALYZER, true);
					options.setBoolean(OBJC_METADATA_ANALYZER, true);
					options.setBoolean(SWIFT_METADATA_ANALYZER, true);
					commit = true;
				}
				finally {
					program.endTransaction(tx, commit);
				}
				monitor.setMessage("Scheduling re-analysis");
				AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
				mgr.reAnalyzeAll(null);
				mgr.startAnalysis(monitor);
				plugin.getProvider().postSystemMessage(
					"[apple] Enabled ObjC/Swift analyzers and re-ran analysis on " +
						program.getName() + " (" + ctx.summary() + ").");
			}
		});
	}
}
