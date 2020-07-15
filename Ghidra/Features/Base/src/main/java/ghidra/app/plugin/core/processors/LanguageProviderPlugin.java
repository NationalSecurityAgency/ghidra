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
package ghidra.app.plugin.core.processors;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.store.LockException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Set Language",
	description = "This plugin provides the set language feature."
)
//@formatter:on
public final class LanguageProviderPlugin extends Plugin implements FrontEndable {

	private DockingAction setLanguageAction;

	public LanguageProviderPlugin(PluginTool plugintool) {
		super(plugintool);
	}

	@Override
	protected void init() {
		if (!(tool instanceof FrontEndTool)) {
			return;
		}

		setLanguageAction = new DockingAction("Set Language", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				DomainFile file = getDomainFile((ProjectDataContext) context);
				if (file != null) {
					setLanguage(file);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext actionContext) {
				if (!(actionContext instanceof ProjectDataContext)) {
					return false;
				}
				ProjectDataContext context = (ProjectDataContext) actionContext;
				DomainFile file = getDomainFile(context);
				if (file == null) {
					return false;
				}

				return file.isInWritableProject() &&
					Program.class.isAssignableFrom(file.getDomainObjectClass());
			}

			private DomainFile getDomainFile(ProjectDataContext context) {
				if (context.getFileCount() == 1 && context.getFolderCount() == 0) {
					return context.getSelectedFiles().get(0);
				}
				return null;
			}

			@Override
			public void dispose() {
				super.dispose();
			}

		};
		setLanguageAction.setPopupMenuData(
			new MenuData(new String[] { "Set Language..." }, "Language"));

		setLanguageAction.setEnabled(true);
		setLanguageAction.setHelpLocation(
			new HelpLocation("LanguageProviderPlugin", "set language"));
		tool.addAction(setLanguageAction);
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// methods overriding Plugin                                        //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	@Override
	public void dispose() {
		if (tool != null) {
			if (setLanguageAction != null) {
				tool.removeAction(setLanguageAction);
			}
		}
		super.dispose();
	}

	private void setLanguage(DomainFile domainFile) {

		String dfName = domainFile.getName();

		if (domainFile.isReadOnly()) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "Permission Denied", "Program " + dfName +
				" is read-only!\n" + "Set language may not be done on a read-only Program.");
			return;
		}

		if (!domainFile.getConsumers().isEmpty() || domainFile.isBusy()) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "File In-Use",
				"Program " + dfName + " is in-use!\n" +
					"Set language may not be done while the associated file is\n" +
					"open or in-use.  Be sure the file is not open in a tool.");
			return;
		}

		if (domainFile.isCheckedOut() && !domainFile.isCheckedOutExclusive()) {
			String msg = (domainFile.modifiedSinceCheckout() || domainFile.isChanged())
					? "check-in this file"
					: "undo your checkout";

			Msg.showInfo(getClass(), tool.getToolFrame(), "Exclusive Checkout Required",
				"You do not have an exclusive checkout of: " + dfName + "\n \n" +
					"An exclusive checkout is required in order to\n" +
					"change the current language associated with\n" +
					"the selected Program file.  Be sure the file is\n" + "not open in a tool, " +
					msg + ", then\n" + "do a checkout with the exclusive lock.");
			return;
		}

		String msg = "Setting the language can not be undone!\n";

		if (domainFile.modifiedSinceCheckout()) {
			msg += "\nIt is highly recommended that you check-in your recent\n" +
				"changes before performing this operation.";
		}
		else if (!domainFile.isCheckedOut()) {
			msg += "\nIt is highly recommended that you make a copy of the\n" +
				"selected file before performing this operation.";
		}

		ToolTemplate defaultToolTemplate =
			tool.getToolServices().getDefaultToolTemplate(domainFile);
		String toolMsg = defaultToolTemplate == null
				? "WARNING! Without a default tool the file " +
					"will be overwritten\nwhen the Set Language is complete."
				: "When complete you can Save the results or Open the results\nin the " +
					defaultToolTemplate.getName() + " tool";

		int result = OptionDialog.showOptionDialog(tool.getToolFrame(), "Set Language: " + dfName,
			msg + "\n \n" + toolMsg + "\n \nDo you want to continue?", "Ok",
			OptionDialog.WARNING_MESSAGE);
		if (result > 0) {
			final SetLanguageTask task = new SetLanguageTask(domainFile);
			new TaskLauncher(task, tool.getToolFrame(), 0);

			if (task.openTool != null) {
				SwingUtilities.invokeLater(() -> task.openTool.getToolFrame().requestFocus());
			}
		}
	}

	private class SetLanguageTask extends Task {

		DomainFile domainFile;
		PluginTool openTool;

		public SetLanguageTask(DomainFile domainFile) {
			super("Setting Language: " + domainFile.getName(), true, true, true);
			this.domainFile = domainFile;
		}

		@Override
		public void run(TaskMonitor monitor) {

			DomainObject dobj = null;
			try {
				monitor.setMessage("Open " + domainFile.getName() + "...");
				dobj = domainFile.getDomainObject(tool, true, false, monitor);
				if (domainFile.getConsumers().size() != 1 || !dobj.canSave() ||
					!dobj.hasExclusiveAccess()) {
					Msg.showError(this, null, "Set Language Error",
						"Program file in-use or exclusive update not possible.");
					monitor.cancel();
				}
				dobj.setTemporary(true); // prevent snapshot or other undesired use
				Program program = (Program) dobj;

				monitor.setMessage("Identify Language...");
				SetLanguageDialog dialog = new SetLanguageDialog(tool, program);
				LanguageID langDescID = dialog.getLanguageDescriptionID();
				CompilerSpecID compilerSpecDescID = dialog.getCompilerSpecDescriptionID();
				if ((langDescID == null) || (compilerSpecDescID == null)) {
					monitor.cancel();
					return;
				}

				boolean success = setLanguage(monitor, program, langDescID, compilerSpecDescID);
				if (!success) {
					return;
				}

				ToolTemplate toolTemplate =
					tool.getToolServices().getDefaultToolTemplate(program.getDomainFile());
				if (toolTemplate == null) {
					program.save(null, monitor);
					return;
				}

				int option =
					OptionDialog.showOptionDialog(tool.getToolFrame(), "Set Language Completed",
						"Would you like to Save the modified program file or Open it in the " +
							toolTemplate.getName() + " tool?",
						"Save", "Open", OptionDialog.QUESTION_MESSAGE);
				if (option == OptionDialog.OPTION_ONE) {
					// option 1 is 'Save'
					program.save(null, monitor);
				}
				else if (option == OptionDialog.OPTION_TWO) {
					// option 2 is 'Open'
					monitor.setCancelEnabled(false);
					program.setTemporary(false);
					openFile(domainFile);
				}
			}
			catch (VersionException e) {
				Msg.showError(this, null, "Set Language Failed",
					"File was created with a newer version of Ghidra\nand cannot be read.");
				return;
			}
			catch (CancelledException e) {
				// user cancelled
			}
			catch (IOException e) {
				Msg.showError(this, null, "File Error", e.toString(), e);
			}
			finally {
				if (dobj != null) {
					dobj.release(tool);
				}
			}
		}

		private boolean setLanguage(TaskMonitor monitor, Program program, LanguageID langDescID,
				CompilerSpecID compilerSpecDescID) throws LanguageNotFoundException {

			monitor.setMessage("Setting Language & Compiler Spec...");
			int txId = program.startTransaction("Set Language");
			boolean success = false;
			try {
				program.setLanguage(
					DefaultLanguageService.getLanguageService().getLanguage(langDescID),
					compilerSpecDescID, false, monitor);
				success = true;
			}
			catch (IllegalStateException e) {
				if (!monitor.isCancelled()) {
					Throwable t = e.getCause();
					if (t == null) {
						t = e;
					}
					Msg.showError(this, null, "Set Language Error", t.toString(), t);
					monitor.cancel();
				}
			}
			catch (IncompatibleLanguageException e) {
				Msg.showError(this, null, "Set Language Failed",
					"Incompatible Language: " + e.getMessage());
				monitor.cancel();
			}
			catch (LockException e) {
				Msg.showError(this, null, "Set Language Failed",
					"Program not checked out exclusively: " + e.toString());
				monitor.cancel();
			}
			finally {
				program.endTransaction(txId, success);
			}
			return success;
		}

		private void openFile(final DomainFile file) {
			try {
				SwingUtilities.invokeAndWait(() -> {
					ToolServices toolServices = tool.getToolServices();
					String defaultToolName = toolServices.getDefaultToolTemplate(file).getName();
					for (PluginTool t : toolServices.getRunningTools()) {
						if (t.getName().equals(defaultToolName)) {
							openTool = t;
							break;
						}
					}
					if (openTool != null) {
						openTool.acceptDomainFiles(new DomainFile[] { file });
					}
					else {
						openTool = tool.getToolServices().launchDefaultTool(file);
					}
				});
			}
			catch (InterruptedException e) {
				// don't care?
			}
			catch (InvocationTargetException e) {
				Throwable t = e.getCause();
				Msg.showError(this, tool.getToolFrame(), "Tool Launch Failed",
					"An error occurred while attempting to launch your default tool!", t);
			}
		}
	}
}
