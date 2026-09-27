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

import ghidra.app.util.HelpTopics;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.DataTreeDialogType;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

public class CreateProjectArchiveDialog extends DataTreeDialog {

	private Object consumer;
	private ProjectDataTypeArchive archive;

	public CreateProjectArchiveDialog(Object consumer) {
		super(null, "Create Project Archive", DataTreeDialogType.CREATE);
		this.consumer = consumer;
		setHelpLocation(new HelpLocation(HelpTopics.DATA_MANAGER, "New_Project_Data_Type_Archive"));
	}

	public ProjectDataTypeArchive getArchive() {
		return archive;
	}

	@Override
	protected void okCallback() {
		DomainFolder folder = getDomainFolder();
		String name = getNameText();
		if (name.length() == 0) {
			setStatusText("Please enter a name");
			return;
		}
		if (folder == null) {
			setStatusText("Please select a folder");
			return;
		}
		DomainFile file = folder.getFile(name);
		if (file != null) {
			setStatusText("Choose a name that doesn't exist");
			return;
		}
		if (createArchive()) {
			close();
		}
	}

	private boolean createArchive() {
		DomainFolder domainFolder = getDomainFolder();
		String archiveName = getNameText();
		try {
			archive =
				DataTypeArchiveFactory.createProjectArchive(domainFolder, archiveName, consumer);
			return true;
		}
		catch (DuplicateNameException e) {
			setStatusText("Duplicate Name: " + e.getMessage());
		}
		catch (InvalidNameException e) {
			setStatusText("Invalid Name: " + e.getMessage());
		}
		catch (IOException e) {
			setStatusText("Unexpected IOException!");
			Msg.showError(null, getComponent(), "Unexpected Exception", e.getMessage(), e);
		}
		return false;
	}
}
