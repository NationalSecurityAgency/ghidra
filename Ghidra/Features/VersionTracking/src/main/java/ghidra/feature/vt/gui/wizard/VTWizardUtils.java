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
package ghidra.feature.vt.gui.wizard;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import docking.widgets.OptionDialog;
import ghidra.feature.vt.api.impl.VTSessionContentHandler;
import ghidra.feature.vt.gui.task.SaveTask;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFileFilter;
import ghidra.program.database.ProgramDB;
import ghidra.util.HTMLUtilities;
import ghidra.util.task.TaskLauncher;

public class VTWizardUtils {

	private static class DomainFileBox {
		DomainFile df;
	}

	public static final DomainFileFilter VT_SESSION_FILTER = new DomainFileFilter() {
		@Override
		public boolean accept(DomainFile df) {
			if (VTSessionContentHandler.CONTENT_TYPE.equals(df.getContentType())) {
				return true;
			}
			return false;
		}
	};

	public static final DomainFileFilter PROGRAM_FILTER = new DomainFileFilter() {
		@Override
		public boolean accept(DomainFile df) {
			if (ProgramDB.CONTENT_TYPE.equals(df.getContentType())) {
				return true;
			}
			return false;
		}
	};

	static DomainFile chooseDomainFile(Component parent, String domainIdentifier,
			DomainFileFilter filter, DomainFile fileToSelect) {
		final DataTreeDialog dataTreeDialog = filter == null
				? new DataTreeDialog(parent, "Choose " + domainIdentifier, DataTreeDialog.OPEN)
				: new DataTreeDialog(parent, "Choose " + domainIdentifier, DataTreeDialog.OPEN,
					filter);
		final DomainFileBox box = new DomainFileBox();
		dataTreeDialog.addOkActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				box.df = dataTreeDialog.getDomainFile();
				if (box.df == null) {
					return;
				}
				dataTreeDialog.close();
			}
		});
		dataTreeDialog.selectDomainFile(fileToSelect);
		dataTreeDialog.showComponent();
		return box.df;
	}

	static public boolean askUserToSave(Component parent, DomainFile domainFile) {

		String filename = domainFile.getName();
		int result = OptionDialog.showYesNoDialog(parent, "Save Version Tracking Changes?",
			"<html>Unsaved Version Tracking changes found for session: " +
				HTMLUtilities.escapeHTML(filename) + ".  <br>" +
				"Would you like to save these changes?");

		boolean doSave = result == OptionDialog.YES_OPTION;
		if (doSave) {
			SaveTask saveTask = new SaveTask(domainFile);
			new TaskLauncher(saveTask, parent);
			return saveTask.didSave();
		}
		return false;
	}

	// returns false if the operation was cancelled or the user tried to save but it failed.
	static public boolean askUserToSaveBeforeClosing(Component parent, DomainFile domainFile) {

		String filename = domainFile.getName();
		int result = OptionDialog.showYesNoCancelDialog(parent, "Save Version Tracking Changes?",
			"<html>Unsaved Version Tracking changes found for session: " +
				HTMLUtilities.escapeHTML(filename) + ".  <br>" +
				"Would you like to save these changes?");

		if (result == OptionDialog.CANCEL_OPTION) {
			return false;
		}
		boolean doSave = result == OptionDialog.YES_OPTION;
		if (doSave) {
			SaveTask saveTask = new SaveTask(domainFile);
			new TaskLauncher(saveTask, parent);
			return saveTask.didSave();
		}
		return true;
	}

}
