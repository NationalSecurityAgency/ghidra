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
package ghidra.features.base.values;

import java.io.IOException;

import javax.swing.JTextField;

import docking.Tool;
import docking.widgets.values.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Value class for {@link Program} files. The editor component consists of the {@link JTextField} 
 * and a browse button for bringing up a {@link DataTreeDialog} for picking programs from the 
 * current project. This class also provides a convenience method for opening a program.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class ProgramFileValue extends ProjectFileValue {

	/**
	 * Constructor for creating a new ProgramFileValue with the given name.
	 * @param name the name of the value
	 */
	public ProgramFileValue(String name) {
		this(name, null);
	}

	/**
	 * Constructor for creating a new ProgramFileValue with the given name and a starting
	 * folder when using the project file chooser.
	 * @param name the name of the value
	 * @param startingPath the path to a starting folder
	 */
	public ProgramFileValue(String name, String startingPath) {
		this(name, AppInfo.getActiveProject(), startingPath);
	}

	/**
	 * Constructor for ProgramValue when wanting to pick from a different project than the
	 * active project, such as a read-only project.
	 * @param name the name of the value
	 * @param project The project from which to pick a project.
	 * @param startingPath the path to a starting folder (Can also be a path to program)
	 */
	public ProgramFileValue(String name, Project project, String startingPath) {
		super(name, project, startingPath, Program.class);
	}

	/**
	 * Convenience method for opening the program for the current program file value. If the program
	 * is already open, then the consumer will be added to the program. The caller of this method is
	 * responsible for calling {@link Program#release(Object)} with the same consumer when it is
	 * done using this program. Program are only closed after all consumers are released. If
	 * multiple calls are made to this method, then the consumer will be added multiple times
	 * and must be released multiple times.
	 * <P>
	 * The consumer can be any object, but since the consumer's purpose is to keep the program open 
	 * while some object is using it, the object itself is typically passed in as
	 * the consumer. For example, when used in a script, passing in the java keyword "this" as the
	 * consumer will make the script itself the consumer.
	 * <P>
	 * @param consumer the consumer to be used to open the program
	 * @param tool optional tool that if non-null, the program will also be opened in the tool
	 * @param monitor task monitor for cancelling the open program.
	 * @return a program for the current program value value. If the current program file value
	 * is null, then null will be returned.
	 * @throws VersionException if the Program being opened is an older version than the 
	 * current Ghidra Program version.
	 * @throws IOException if there is an error accessing the Program's DomainObject
	 * @throws CancelledException if the operation is cancelled
	 */
	public Program openProgram(Object consumer, Tool tool, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		DomainFile domainFile = getValue();
		if (domainFile == null) {
			return null;
		}

		Program program = (Program) domainFile.getDomainObject(consumer, true, false, monitor);

		if (tool != null && program != null) {
			tool.getService(ProgramManager.class).openProgram(program);
		}
		return program;
	}

}
