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
package ghidra.app.plugin.core.datamgr;

import java.io.IOException;
import java.rmi.ConnectException;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DataTypeArchiveSaveTask extends Task {
	private static final String CONTENT_NAME = "Data Type Archive";
	private PersistentDataTypeArchive archive;
	private PluginTool tool;

	DataTypeArchiveSaveTask(PersistentDataTypeArchive archive, PluginTool tool) {
		super("Save " + archive.getName(), true, true, true);
		this.archive = archive;
		this.tool = tool;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage("Saving " + archive.getName() + "...");
		if (acquireSaveLock(archive)) {
			try {
				archive.save(null, monitor);
			}
			catch (CancelledException e) {
				// O.K., expected
			}
			catch (NotConnectedException e) {
				ClientUtil.promptForReconnect(tool.getProject().getRepository(),
					tool.getToolFrame());
			}
			catch (ConnectException e) {
				ClientUtil.promptForReconnect(tool.getProject().getRepository(),
					tool.getToolFrame());
			}
			catch (IOException e) {
				ClientUtil.handleException(tool.getProject().getRepository(), e, "Save File",
					tool.getToolFrame());
			}
			finally {
				archive.unlock();
			}
		}
	}

	private boolean acquireSaveLock(DomainObject domainObject) {
		if (!domainObject.lock(null)) {
			String title = "Save " + CONTENT_NAME + " (Busy)";
			StringBuilder buf = new StringBuilder();
			buf.append("The " + CONTENT_NAME + " is currently being modified by \n");
			buf.append("the following actions:\n ");
			TransactionInfo t = domainObject.getCurrentTransactionInfo();
			List<String> list = t.getOpenSubTransactions();
			for (String element : list) {
				buf.append("\n     ");
				buf.append(element);
			}
			buf.append("\n \n");
			buf.append(
				"WARNING! The above task(s) should be cancelled before attempting a Save.\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append(
				"If you continue, all changes made by these tasks, as well as any other overlapping task,\n");
			buf.append(
				"will be LOST and subsequent transaction errors may occur while these tasks remain active.\n \n");

			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title, buf.toString(),
				"Save Archive!", OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				domainObject.forceLock(true, "Save Archive");
				return true;
			}
			return false;
		}
		return true;
	}

}
