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
package ghidra.framework.main;

import java.awt.Component;

import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;

/**
 * {@link ProgramFileChooser} facilitates selection of an existing project Program file including
 * Program link-files which may link to either internal or external program files.
 * This chooser operates in the {@link DataTreeDialogType#OPEN open mode} for selecting
 * an existing file only.  
 * <P>
 * This chooser should not be used to facilitate an immediate or 
 * future save-as operation or to open a Program for update since it can return a read-only file.
 * A more taylored {@link DataTreeDialog} should be used for case where the file will be written. 
 */
public class ProgramFileChooser extends DataTreeDialog {

	/**
	 * This file filter permits selection of any program including those than can be 
	 * found by following bother internal and external folder and files links.
	 */
	public static final DomainFileFilter PROGRAM_FILE_FILTER =
		new DefaultDomainFileFilter(Program.class, false);

	/**
	 * Construct a new ProgramChooser for the active project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public ProgramFileChooser(Component parent, String title) {
		super(parent, title, DataTreeDialogType.OPEN, PROGRAM_FILE_FILTER);
	}

	/**
	 * Construct a new DataTreeDialog for the given project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param project the project to browse
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public ProgramFileChooser(Component parent, String title, Project project) {
		super(parent, title, DataTreeDialogType.OPEN, PROGRAM_FILE_FILTER, project);
	}

}
