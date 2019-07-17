/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.exception.DuplicateFileException;

import java.awt.Component;
import java.io.IOException;

import javax.swing.ImageIcon;

import resources.ResourceManager;

public class BuiltInArchive implements Archive {

	private static ImageIcon CLOSED_ICON = ResourceManager.loadImage("images/closedBookBrown.png");
	private static ImageIcon OPEN_ICON = ResourceManager.loadImage("images/openBookBrown.png");
	private DataTypeManagerHandler archiveManager;
	private BuiltInDataTypeManager dataTypeManager;

	BuiltInArchive(DataTypeManagerHandler archiveManager, BuiltInDataTypeManager dataTypeManager) {
		this.archiveManager = archiveManager;
		this.dataTypeManager = dataTypeManager;
	}

	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	public String getName() {
		return dataTypeManager.getName();
	}

	public int compareTo(Archive archive) {
		return -1; // Built-ins are always at the top 
	}

	public boolean isModifiable() {
		return false; // Can't change the data types that are in Built-Ins.
	}

	public void close() {
		// Not allowed to close the Built In Data Type Manager.
	}

	public boolean isChanged() {
		return false; // Can't change.
	}

	public boolean isSavable() {
		return false; // Can't save.
	}

	public void save() throws DuplicateFileException, IOException {
		// Can't "Save" so do nothing.
	}

	public void saveAs(Component component) throws IOException {
		// Can't "Save As" so do nothing.
	}

	public ImageIcon getIcon(boolean expanded) {
		return expanded ? OPEN_ICON : CLOSED_ICON;
	}
}
