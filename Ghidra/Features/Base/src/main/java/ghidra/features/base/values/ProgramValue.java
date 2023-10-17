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

import javax.swing.JComponent;
import javax.swing.JTextField;

import docking.Tool;
import docking.widgets.values.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Value class for {@link Program}s. The editor component consists of the {@link JTextField} and
 * a browse button for bringing up a {@link DataTreeDialog} for picking programs from the 
 * current project.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class ProgramValue extends AbstractValue<Program> {

	private ProjectBrowserPanel domainFilePanel;
	private Tool tool;
	private Object consumer;

	/**
	 * Construct for ProgramValue
	 * @param name the name of the value
	 * @param consumer the program consumer to be used to open a program
	 * @param tool if non null, the program will also be opened in this tool
	 */
	public ProgramValue(String name, Object consumer, Tool tool) {
		this(name, null, consumer, tool);
	}

	/**
	 * Construct for ProgramValue
	 * @param name the name of the value
	 * @param defaultValue the program to use as the default value
	 * @param consumer the program consumer to be used to open a program
	 * @param tool if non null, the program will also be opened in this tool
	 */
	public ProgramValue(String name, Program defaultValue, Object consumer, Tool tool) {
		super(name, defaultValue);
		this.consumer = consumer;
		this.tool = tool;
	}

	@Override
	public JComponent getComponent() {
		if (domainFilePanel == null) {
			domainFilePanel = new ProjectBrowserPanel(getName(), false);
		}
		return domainFilePanel;
	}

	@Override
	protected void updateValueFromComponent() throws ValuesMapParseException {
		if (domainFilePanel != null) {
			DomainFile domainFile = domainFilePanel.getDomainFile();
			if (domainFile == null) {
				String text = domainFilePanel.getText();
				if (text.isBlank()) {
					setValue(null);
					return;
				}
				throw new ValuesMapParseException(getName(), "Program",
					"No file found for \"" + text + "\"");
			}
			Program program = openProgram(domainFile);
			setValue(program);
		}
	}

	private Program openProgram(DomainFile domainFile) throws ValuesMapParseException {
		if (domainFile == null) {
			return null;
		}
		Class<? extends DomainObject> domainObjectClass = domainFile.getDomainObjectClass();
		if (!Program.class.isAssignableFrom(domainObjectClass)) {
			return null;
		}
		try {
			Program program =
				(Program) domainFile.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);

			if (tool != null && program != null) {
				tool.getService(ProgramManager.class).openProgram(program);
			}
			return program;
		}
		catch (VersionException | CancelledException | IOException e) {
			throw new ValuesMapParseException(getName(), "Program", e.getMessage());
		}
	}

	@Override
	protected void updateComponentFromValue() {
		Program program = getValue();
		DomainFile df = program == null ? null : program.getDomainFile();
		domainFilePanel.setDomainFile(df);
	}

	@Override
	protected Program fromString(String valueString) {
		DomainFile programFile = ProjectBrowserPanel.parseDomainFile(valueString);
		if (programFile == null) {
			throw new IllegalArgumentException("Could not find program " + valueString);
		}
		try {
			Program program = openProgram(programFile);
			if (program == null) {
				throw new IllegalArgumentException("Can't open program: " + valueString);
			}
			return program;
		}
		catch (ValuesMapParseException e) {
			throw new IllegalArgumentException(e.getMessage());
		}
	}

	@Override
	protected String toString(Program v) {
		return v.getDomainFile().getPathname();
	}

}
