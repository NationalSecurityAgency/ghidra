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
package ghidra.app.plugin.core.debug.gui.copying;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.action.DebuggerProgramLocationActionContext;
import ghidra.app.plugin.core.exporter.ExporterDialog;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceVariableSnapProgramView;

//@formatter:off
@PluginInfo(
	shortDescription = "Copy and export trace data",
	description = "Provides tool actions for moving data from traces to various destinations.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {},
	eventsProduced = {},
	servicesRequired = {
		DebuggerStaticMappingService.class,
		ProgramManager.class,
	},
	servicesProvided = {})
//@formatter:on
public class DebuggerCopyActionsPlugin extends AbstractDebuggerPlugin {

	protected static ProgramSelection getSelectionFromContext(ActionContext context) {
		if (!(context instanceof ProgramLocationActionContext)) {
			return null;
		}
		ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
		return ctx.hasSelection() ? ctx.getSelection() : null;
	}

	protected DebuggerCopyIntoProgramDialog copyDialog;

	protected DockingAction actionExportView;
	protected DockingAction actionCopyIntoCurrentProgram;
	protected DockingAction actionCopyIntoNewProgram;

	@AutoServiceConsumed
	private ProgramManager programManager;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerTargetService targetService;

	public DebuggerCopyActionsPlugin(PluginTool tool) {
		super(tool);
		copyDialog = new DebuggerCopyIntoProgramDialog(tool);

		createActions();
	}

	@Override
	protected void dispose() {
		super.dispose();

		copyDialog.dispose();
	}

	protected void createActions() {
		actionExportView = ExportTraceViewAction.builder(this)
				.enabled(false)
				.withContext(DebuggerProgramLocationActionContext.class, true)
				.onAction(this::activatedExportView)
				.buildAndInstall(tool);

		// Using programManager here depends on it calling tool.updateContext()
		actionCopyIntoCurrentProgram = CopyIntoCurrentProgramAction.builder(this)
				.enabled(false)
				.withContext(DebuggerProgramLocationActionContext.class, true)
				.enabledWhen(
					ctx -> ctx.hasSelection() && programManager.getCurrentProgram() != null)
				.onAction(this::activatedCopyIntoCurrentProgram)
				.buildAndInstall(tool);

		actionCopyIntoNewProgram = CopyIntoNewProgramAction.builder(this)
				.enabled(false)
				.withContext(DebuggerProgramLocationActionContext.class, true)
				.enabledWhen(DebuggerProgramLocationActionContext::hasSelection)
				.onAction(this::activatedCopyIntoNewProgram)
				.buildAndInstall(tool);
	}

	protected void activatedExportView(DebuggerProgramLocationActionContext context) {
		TraceProgramView view = context.getProgram();
		// Avoid odd race conditions by fixing the snap
		TraceProgramView fixed = view instanceof TraceVariableSnapProgramView
				? view.getTrace().getFixedProgramView(view.getSnap())
				: view;

		ExporterDialog dialog =
			new ExporterDialog(tool, fixed.getDomainFile(), fixed,
				getSelectionFromContext(context));
		tool.showDialog(dialog);
	}

	protected void activatedCopyIntoCurrentProgram(DebuggerProgramLocationActionContext context) {
		if (!context.hasSelection()) {
			return;
		}
		copyDialog.setSource(context.getProgram(), context.getSelection());
		copyDialog.setProgramManager(programManager);
		copyDialog.setStaticMappingService(mappingService);
		copyDialog.setTargetService(targetService);
		copyDialog.setDestination(programManager.getCurrentProgram());
		copyDialog.reset();
		copyDialog.setStatusText("");
		tool.showDialog(copyDialog);
	}

	protected void activatedCopyIntoNewProgram(DebuggerProgramLocationActionContext context) {
		if (!context.hasSelection()) {
			return;
		}
		copyDialog.setSource(context.getProgram(), context.getSelection());
		copyDialog.setProgramManager(programManager);
		copyDialog.setStaticMappingService(mappingService);
		copyDialog.setTargetService(targetService);
		copyDialog.setDestination(copyDialog.NEW_PROGRAM);
		copyDialog.reset();
		copyDialog.setStatusText("");
		tool.showDialog(copyDialog);
	}
}
