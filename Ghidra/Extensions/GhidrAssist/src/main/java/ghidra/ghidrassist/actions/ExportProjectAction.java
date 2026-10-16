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

import java.io.File;
import java.nio.file.Path;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.ghidrassist.ClaudeOptions;
import ghidra.ghidrassist.GhidrAssistPlugin;
import ghidra.ghidrassist.ProjectExporter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Tool-menu action that exports the current program as a buildable-ish C
 * project under a user-selected directory. See
 * {@link ghidra.ghidrassist.ProjectExporter} for the honest limits of this
 * feature.
 */
public class ExportProjectAction extends DockingAction {

	private final GhidrAssistPlugin plugin;

	public ExportProjectAction(GhidrAssistPlugin plugin) {
		super("GhidrAssist Export C Project", plugin.getName());
		this.plugin = plugin;
		setMenuBarData(new MenuData(new String[] { "Tools", "GhidrAssist", "Export C Project…" },
			null, "GhidrAssist"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return plugin.getCurrentProgram() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			return;
		}

		SwingUtilities.invokeLater(() -> {
			GhidraFileChooser chooser = new GhidraFileChooser(null);
			chooser.setTitle("GhidrAssist: Choose output directory");
			chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			File dir = chooser.getSelectedFile();
			chooser.dispose();
			if (dir == null) {
				return;
			}

			ClaudeOptions opts = plugin.options();
			boolean canClean = opts.isConfigured();
			int cleanChoice = OptionDialog.showYesNoCancelDialog(null,
				"GhidrAssist — Claude cleanup?",
				canClean
						? "Run every function through Claude for a cleanup pass before writing?\n" +
							"This can take a while and uses API quota.\n\n" +
							"Yes = Claude-clean every function\nNo = raw decompiler output only"
						: "No API key configured; functions will be exported as raw " +
							"decompiler output. Continue?");
			if (cleanChoice == OptionDialog.CANCEL_OPTION) {
				return;
			}
			boolean claudeClean = canClean && cleanChoice == OptionDialog.YES_OPTION;

			TaskLauncher.launch(new Task("GhidrAssist: Export C project", true, true, true) {
				@Override
				public void run(TaskMonitor monitor) {
					try {
						ProjectExporter.Result r = ProjectExporter.export(program, dir.toPath(),
							claudeClean, plugin.claude(), opts, monitor);
						Path out = r.outputDir();
						plugin.getProvider().postSystemMessage(
							"[export] Wrote " + r.reconstructed() +
								" function(s) to " + out + " (" + r.failed() + " skipped/failed).");
						Msg.showInfo(this, null, "GhidrAssist",
							"Exported C project to:\n" + out +
								"\n\nSee the README in that directory for honest limits.");
					}
					catch (Exception e) {
						Msg.showError(this, null, "GhidrAssist export failed", e.getMessage(), e);
					}
				}
			});
		});
	}
}
