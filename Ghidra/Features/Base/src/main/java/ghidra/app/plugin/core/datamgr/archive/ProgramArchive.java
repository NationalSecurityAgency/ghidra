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

import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeManagerChangeListener;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateFileException;

import java.awt.Component;
import java.io.IOException;

import javax.swing.ImageIcon;

import resources.ResourceManager;

public class ProgramArchive implements DomainFileArchive {

	private static ImageIcon CLOSED_ICON = ResourceManager.loadImage("images/closedBookRed.png");
	private static ImageIcon OPEN_ICON = ResourceManager.loadImage("images/openBookRed.png");
	private final Program program;
	DataTypeManagerChangeListener categoryListener; // hold on to since it is stored in a weak set
	private DataTypeManager dataTypeManager;

	ProgramArchive(Program program) {
		this.program = program;
		this.dataTypeManager = program.getDataTypeManager();
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public String getName() {
		return dataTypeManager.getName();
	}

	@Override
	public int compareTo(Archive archive) {
		if (archive instanceof BuiltInArchive) {
			return 1;
		}
		return -1; // Programs are always before everything else except for built-ins
	}

	@Override
	public boolean isModifiable() {
		return true;
	}

	@Override
	public void close() {
		// Can't directly close the program archive. Instead you must close the Program.
	}

	@Override
	public boolean isChanged() {
		return false;
	}

	@Override
	public boolean isSavable() {
		return false;
	}

	@Override
	public void save() throws DuplicateFileException, IOException {
		// Can't "Save" so do nothing.
	}

	@Override
	public void saveAs(Component component) throws IOException {
		// Can't "Save As" so do nothing.
	}

	@Override
	public DomainFile getDomainFile() {
		return program.getDomainFile();
	}

	@Override
	public Program getDomainObject() {
		return program;
	}

	@Override
	public ImageIcon getIcon(boolean expanded) {
		return expanded ? OPEN_ICON : CLOSED_ICON;
	}
}
