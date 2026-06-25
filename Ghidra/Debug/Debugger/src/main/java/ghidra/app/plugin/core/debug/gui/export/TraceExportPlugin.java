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
package ghidra.app.plugin.core.debug.gui.export;

import java.io.File;
import java.util.Map;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.utils.GztExporter;
import ghidra.app.plugin.core.help.AboutDomainObjectUtils;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Swing;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	shortDescription = "Export Debugger Trace",
	description = "This plugin exports a Debugger Trace to an external file.",
	servicesRequired = {
		DebuggerTraceManagerService.class
	}
)
//@formatter:on
public class TraceExportPlugin extends Plugin {

	private DebuggerTraceManagerService traceMgrSvc;

	public TraceExportPlugin(PluginTool tool) {
		super(tool);
		createToolAction();
	}

	@Override
	protected void init() {
		traceMgrSvc = tool.getService(DebuggerTraceManagerService.class);
	}

	private void createToolAction() {

		new ActionBuilder("Export Trace", getName())
				.description("Export Debbuger Trace as compressed GZT file.")
				// .helpLocation(new HelpLocation("ExporterPlugin", "Export"))
				.menuPath(ToolConstants.MENU_FILE, "Export Trace...")
				.menuGroup("DomainObjectSaveExport")
				.enabledWhen(c -> getTrace(c) != null)
				.onAction(c -> exportTrace(c))
				.buildAndInstall(tool);
	}

	private Trace getTrace(ActionContext ctx) {
		if (ctx instanceof ProgramActionContext programCtx) {
			Program p = programCtx.getProgram();
			if (p instanceof TraceProgramView traceProgrmView) {
				return traceProgrmView.getTrace();
			}
		}
		return traceMgrSvc.getCurrentTrace();
	}

	private void exportTrace(ActionContext ctx) {

		Trace trace = getTrace(ctx);
		if (trace == null) {
			return;
		}

		File file = chooseDestinationFile(ctx);
		if (file == null) {
			return; // file chooser cancelled
		}

		File gztFile = file;
		GztExporter exporter = new GztExporter();

		TaskLauncher.launchModal("Export Trace", m -> {
			exporter.export(gztFile, trace, null, m);
		});

		displaySummaryResults(trace, gztFile, exporter.getMessageLog());
	}

	private File chooseDestinationFile(ActionContext ctx) {
		GhidraFileChooser chooser = new GhidraFileChooser(ctx.getSourceComponent());
		chooser.setCurrentDirectory(getLastExportDirectory());
		chooser.setTitle("Select Trace Output File");
		chooser.setApproveButtonText("Export Trace");
		chooser.setApproveButtonToolTipText("Export Debugger Trace");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		chooser.setFileFilter(
			new ExtensionFileFilter(GztExporter.EXTENSION, GztExporter.NAME));

		File file;
		while (true) {
			file = chooser.getSelectedFile();
			if (file == null) {
				break;
			}
			setLastExportDirectory(file);
			if (!file.getName().endsWith(GztExporter.SUFFIX)) {
				file = new File(file.getParent(), file.getName() + GztExporter.SUFFIX);
			}
			if (!file.exists()) {
				break; // continue with file return
			}
			if (!file.isFile()) {
				chooser.setStatusText("Invalid File Selection");
				continue;
			}
			int rc = OptionDialog.showYesNoCancelDialog(chooser.getComponent(),
				"Overwrite Confirmation",
				"Overwrite Trace export file?\n" + file);
			if (rc == OptionDialog.YES_OPTION) {
				break; // continue with file return
			}
			file = null; // don't overwrite
			if (rc != OptionDialog.NO_OPTION) {
				break; // continue with null return / export cancelled
			}
		}
		chooser.dispose();
		return file;
	}

	private File getLastExportDirectory() {
		String lastDirStr = Preferences.getProperty(Preferences.LAST_EXPORT_DIRECTORY,
			System.getProperty("user.home"), true);
		return new File(lastDirStr);
	}

	private void setLastExportDirectory(File file) {
		Preferences.setProperty(Preferences.LAST_EXPORT_DIRECTORY, file.getParent());
		Preferences.store();
	}

	protected ProgramSelection getSelection() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service != null) {
			return service.getCurrentSelection();
		}
		return null;
	}

	private void displaySummaryResults(Trace trace, File outputFile, MessageLog log) {

		StringBuffer resultsBuffer = new StringBuffer();

		resultsBuffer.append("Destination file:       " + outputFile.getAbsolutePath() + "\n\n");
		resultsBuffer.append("Destination file Size:  " + outputFile.length() + "\n");
		resultsBuffer.append("Format:                 " + GztExporter.NAME + "\n\n");
		resultsBuffer.append(log.toString());

		Map<String, String> metadata = trace.getMetadata();

		Swing.runLater(() -> {
			AboutDomainObjectUtils.displayInformation(tool, trace.getDomainFile(), metadata,
				"Trace Export Results Summary", resultsBuffer.toString(), null);
		});

	}

}
