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
package ghidra.app.plugin.core.decompiler.taint.actions;

import javax.swing.Icon;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintState.QueryType;
import ghidra.app.plugin.core.decompiler.taint.sarif.SarifTaintGraphRunHandler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import sarif.SarifService;

/**
 * Action triggered from a specific token in the decompiler window to mark a variable as a source or
 * sink and generate the requisite query. This can be an input parameter, a stack variable, a
 * variable associated with a register, or a "dynamic" variable.
 */
public abstract class TaintAbstractQueryAction extends TaintAbstractDecompilerAction {

	protected TaintPlugin plugin;
	protected TaintState state;
	protected String desc;

	protected String executeTaintQueryIconString;
	protected Icon executeTaintQueryIcon;
	protected QueryType queryType;

	public TaintAbstractQueryAction(TaintPlugin plugin, TaintState state, String desc, String cmd) {
		super(cmd);

		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "Taint"+desc));
		setMenuBarData(new MenuData(new String[] { "Source-Sink", getName() }));

		this.plugin = plugin;
		this.state = state;
		this.desc = desc;
	}

	/*
	 * We can only perform a query if we have an index database for this program and we have selected a sink.
	 */
	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();

		Task defaultQueryTask = new Task("Source-Sink Query Task", true, true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				state.setCancellation(false);
				monitor.initialize(program.getFunctionManager().getFunctionCount());
				state.queryIndex(program, tool, queryType);
				state.setCancellation(monitor.isCancelled());
				monitor.clearCancelled();
			}
		};

		// This task will block -- see params above.
		// The blocking is necessary because of the table provider we create below.
		// It is problematic to do GUI stuff in the thread.
		// We still get a progress bar and option to cancel.
		tool.execute(defaultQueryTask);

		if (!state.wasCancelled()) {
			SarifService sarifService = plugin.getSarifService();
			sarifService.getController().setDefaultGraphHander(SarifTaintGraphRunHandler.class);
			sarifService.showSarif(desc, state.getData());

			plugin.consoleMessage("executing query...");
			TaintProvider provider = plugin.getProvider();
			provider.setTaint();

			plugin.consoleMessage("query complete");
			state.setCancellation(false);
		}
		else {
			plugin.consoleMessage("Source-Sink query was cancelled.");

		}
	}
}
