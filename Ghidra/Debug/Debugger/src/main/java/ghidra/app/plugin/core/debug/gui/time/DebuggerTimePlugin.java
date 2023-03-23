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
package ghidra.app.plugin.core.debug.gui.time;

import java.util.Map;
import java.util.Map.Entry;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.RenameSnapshotAction;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.TraceTimeManager;

@PluginInfo(
	shortDescription = "Lists recorded snapshots in a trace",
	description = "Provides the component which lists snapshots and allows navigation",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class
	},
	servicesRequired = {
		DebuggerTraceManagerService.class
	})
public class DebuggerTimePlugin extends AbstractDebuggerPlugin {
	protected DebuggerTimeProvider provider;

	protected DockingAction actionRenameSnapshot;

	public DebuggerTimePlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	@Override
	protected void init() {
		provider = new DebuggerTimeProvider(this);
		super.init();
	}

	protected void createActions() {
		actionRenameSnapshot = RenameSnapshotAction.builder(this)
				.enabled(false)
				.enabledWhen(ctx -> contextGetTraceSnap(ctx) != null)
				.onAction(this::activatedRenameSnapshot)
				.buildAndInstall(tool);
	}

	protected Entry<Trace, Long> contextGetTraceSnap(ActionContext context) {
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			Program program = ctx.getProgram();
			if (program instanceof TraceProgramView) {
				TraceProgramView view = (TraceProgramView) program;
				return Map.entry(view.getTrace(), view.getSnap());
			}
			return null;
		}
		if (context instanceof DebuggerSnapActionContext) {
			DebuggerSnapActionContext ctx = (DebuggerSnapActionContext) context;
			if (ctx.getTrace() != null) {
				return Map.entry(ctx.getTrace(), ctx.getSnap());
			}
			return null;
		}
		return null;
	}

	protected void activatedRenameSnapshot(ActionContext context) {
		Entry<Trace, Long> traceSnap = contextGetTraceSnap(context);
		if (traceSnap == null) {
			return;
		}
		Trace trace = traceSnap.getKey();
		long snap = traceSnap.getValue();
		TraceTimeManager manager = trace.getTimeManager();
		TraceSnapshot snapshot = manager.getSnapshot(snap, false);

		InputDialog dialog = new InputDialog("Rename Snapshot", "Description",
			snapshot == null ? "" : snapshot.getDescription());
		tool.showDialog(dialog);
		if (dialog.isCanceled()) {
			return;
		}
		try (Transaction tx = trace.openTransaction("Rename Snapshot")) {
			if (snapshot == null) {
				snapshot = manager.getSnapshot(snap, true);
			}
			snapshot.setDescription(dialog.getValue());
		}
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		provider.writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		provider.readConfigState(saveState);
	}
}
