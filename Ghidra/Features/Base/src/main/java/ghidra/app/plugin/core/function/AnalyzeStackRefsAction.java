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
package ghidra.app.plugin.core.function;

import java.util.Iterator;

import docking.action.MenuData;
import ghidra.app.cmd.function.FunctionStackAnalysisCmd;
import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.util.HelpTopics;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * <CODE>AnalyzeStackRefsAction</CODE> reanalyze functions stack references.
 */
class AnalyzeStackRefsAction extends ListingContextAction {

	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	AnalyzeStackRefsAction(FunctionPlugin plugin) {
		super("Analyze Function Stack References", plugin.getName());
		this.funcPlugin = plugin;

		setMenuBarData(new MenuData(new String[] { "Analysis", "Analyze Stack" }, null,
			FunctionPlugin.FUNCTION_MENU_SUBGROUP));

		setPopupMenuData(
			new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, "Analyze Stack" },
				null, FunctionPlugin.STACK_MENU_SUBGROUP));

		setHelpLocation(new HelpLocation(HelpTopics.AUTO_ANALYSIS, "Stack_Analyzer"));
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		// get the entry points for all the functions in the current selection/location
		Iterator<Function> iter = funcPlugin.getFunctions(context);
		if (iter.hasNext() == false) {
			String message = "No function at current location";
			ProgramSelection selection = context.getSelection();
			if (selection != null) {
				message = "No functions within current selection";
			}

			funcPlugin.getTool().setStatusInfo("Analyze Stack: " + message);
			return;
		}
		AddressSet funcSet = new AddressSet();
		while (iter.hasNext()) {
			Function func = iter.next();
			funcSet.addRange(func.getEntryPoint(), func.getEntryPoint());
		}

		boolean doNewStackAnalysis = true;
		boolean doLocalAnalysis = true;
		boolean doParameterAnalysis = true;

		Program program = context.getProgram();

		// TODO: THIS MAY NOT BE THE BEST WAY TO get the options to agree with the analysis options!  Advise.
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions("Stack");
		options.registerOption(GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS,
			doNewStackAnalysis, null,
			"Use General Stack Reference Propogator (This works best on most processors)");

		options.registerOption("Create Local Variables", doLocalAnalysis, null,
			"Create Function Local stack variables and references");

		options.registerOption("Create Param Variables", doParameterAnalysis, null,
			"Create Function Parameter stack variables and references");
		doNewStackAnalysis = options.getBoolean(
			GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS, doNewStackAnalysis);
		doLocalAnalysis = options.getBoolean("Create Local Variables", doLocalAnalysis);

		doParameterAnalysis = options.getBoolean("Create Param Variables", doParameterAnalysis);

		BackgroundCommand cmd = null;
		if (doNewStackAnalysis) {
			cmd = new NewFunctionStackAnalysisCmd(funcSet, doParameterAnalysis, doLocalAnalysis,
				true);
		}
		else {
			cmd = new FunctionStackAnalysisCmd(funcSet, doParameterAnalysis, doLocalAnalysis, true);
		}
		funcPlugin.execute(program, cmd);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection()) {
			return true;
		}
		Program program = context.getProgram();
		Address addr = context.getAddress();
		if (program == null || addr == null) {
			return false;
		}
		return program.getListing().getFunctionContaining(addr) != null;
	}
}
