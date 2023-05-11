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
package ghidra.app.plugin.core.progmgr;

import java.io.IOException;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import generic.theme.GIcon;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * Abstract base class for the undo and redo actions. These actions add a listener to the
 * current context program in order to know when to update their enabled state and description.
 */
public abstract class AbstractUndoRedoAction extends DockingAction {
	private PluginTool tool;
	private Program lastProgram;
	private ProgramManagerPlugin plugin;
	private TransactionListener transactionListener;

	public AbstractUndoRedoAction(PluginTool tool, ProgramManagerPlugin plugin, String name,
			String iconId, String keyBinding, String subGroup) {

		super(name, plugin.getName());
		this.tool = tool;
		this.plugin = plugin;

		String[] menuPath = { ToolConstants.MENU_EDIT, "&" + name };
		Icon icon = new GIcon(iconId);
		String group = "Undo";

		MenuData menuData = new MenuData(menuPath, icon, group);
		menuData.setMenuSubGroup(subGroup); // make this appear above the redo menu item
		setMenuBarData(menuData);

		setToolBarData(new ToolBarData(icon, group));
		setKeyBindingData(new KeyBindingData(keyBinding));
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, name));
		setDescription(name);

		addToWindowWhen(ProgramActionContext.class);

		transactionListener = new ContextProgramTransactionListener();
	}

	protected abstract void actionPerformed(Program program) throws IOException;

	protected abstract boolean canPerformAction(Program program);

	protected abstract String getUndoRedoDescription(Program program);

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Program program = getProgram(context);

		// This method gets called whenever the action context changes. We will insert logic
		// here to keep track of the current program context and add a listener
		// so that the action's name, description, and enablement is properly updated as the
		// user makes changes to the program.
		if (program != lastProgram) {
			removeTransactionListener(lastProgram);
			lastProgram = program;
			addTransactionListener(lastProgram);
			updateActionNameAndDescription();
		}
		return canPerformAction(lastProgram);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Program program = getProgram(context);
		if (program == null) {
			return;
		}

		saveCurrentLocationToHistory();

		try {
			actionPerformed(program);
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	private Program getProgram(ActionContext context) {
		if (context instanceof ProgramActionContext) {
			return ((ProgramActionContext) context).getProgram();
		}
		return plugin.getCurrentProgram();
	}

	private void removeTransactionListener(Program program) {
		if (program != null) {
			program.removeTransactionListener(transactionListener);
		}
	}

	private void addTransactionListener(Program program) {
		if (program != null) {
			program.addTransactionListener(transactionListener);
		}
	}

	private void updateAction() {
		updateActionNameAndDescription();
		setEnabled(canPerformAction(lastProgram));
	}

	private void updateActionNameAndDescription() {
		String actionName = getName();
		String description = actionName;

		if (lastProgram != null) {
			actionName += " " + lastProgram.getDomainFile().getName();
			description = actionName;
		}

		if (canPerformAction(lastProgram)) {
			description = HTMLUtilities.toWrappedHTML(
				getName() + " " + HTMLUtilities.escapeHTML(getUndoRedoDescription(lastProgram)));
		}

		getMenuBarData().setMenuItemNamePlain(actionName);
		setDescription(description);
	}

	private void saveCurrentLocationToHistory() {
		GoToService goToService = tool.getService(GoToService.class);
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (goToService != null && historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}

	private class ContextProgramTransactionListener implements TransactionListener {

		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
			// don't care
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			// don't care
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
			updateAction();
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
			// don't care
		}

	}
}
