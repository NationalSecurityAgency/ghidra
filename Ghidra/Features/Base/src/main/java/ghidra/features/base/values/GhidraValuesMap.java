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

import docking.Tool;
import docking.widgets.values.GValuesMap;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Extends GValuesMap to add Ghidra specific types such as Address and Program
 */
public class GhidraValuesMap extends GValuesMap {
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	/**
	 * Sets a task monitor to be used when opening programs. Otherwise, {@link TaskMonitor#DUMMY} is
	 * used.
	 * @param monitor the TaskMonitor to use for opening programs
	 */
	public void setTaskMonitor(TaskMonitor monitor) {
		this.monitor = TaskMonitor.dummyIfNull(monitor);
	}
//==================================================================================================
// Define Value Methods
//==================================================================================================	

	/**
	 * Defines a value of type {@link Address} with no default value.
	 * @param name the name for this value
	 * @param program the program used to get an {@link AddressFactory} for parsing addresses
	 * @return the new AddressValue that was defined.
	 */
	public AddressValue defineAddress(String name, Program program) {
		checkDup(name);
		AddressValue value = new AddressValue(name, null, program);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type {@link Address}
	 * @param name the name for this value
	 * @param defaultValue an option default value
	 * @param program the program used to get an {@link AddressFactory} for parsing addresses
	 * @return the new AddressValue that was defined.
	 */
	public AddressValue defineAddress(String name, Address defaultValue, Program program) {
		checkDup(name);
		AddressValue value = new AddressValue(name, defaultValue, program);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type {@link Address}
	 * @param name the name for this value
	 * @param defaultValue an option default value
	 * @param factory the {@link AddressFactory} used to parse addresses
	 * @return the new AddressValue that was defined.
	 */
	public AddressValue defineAddress(String name, Address defaultValue, AddressFactory factory) {
		checkDup(name);
		AddressValue value = new AddressValue(name, defaultValue, factory);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type LanguageCompilerSpecPair (folders in a Ghidra project).
	 * @param name the name for this value
	 * @param defaultValue the initial value (can be null)
	 * @return the new ProjectFolderValue that was defined
	 */
	public LanguageValue defineLanguage(String name, LanguageCompilerSpecPair defaultValue) {
		checkDup(name);
		LanguageValue value = new LanguageValue(name, defaultValue);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type Program file.
	 * @param name the name for this value
	 * @return the new ProgramFileValue defined 
	 */
	public ProgramFileValue defineProgram(String name) {
		return defineProgram(name, null);
	}

	/**
	 * Defines a value of type Program file.
	 * @param name the name for this value
	 * @param startPath the starting folder to display when picking programs from the chooser
	 * @return the new ProgramFileValue that was defined
	 */
	public ProgramFileValue defineProgram(String name, String startPath) {
		checkDup(name);
		ProgramFileValue value = new ProgramFileValue(name, startPath);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type DomainFile (files in a Ghidra project).
	 * @param name the name for this value
	 * @return the new ProjectFileValue that was defined
	 */
	public ProjectFileValue defineProjectFile(String name) {
		return defineProjectFile(name, null);
	}

	/**
	 * Defines a value of type DomainFile (files in a Ghidra project).
	 * @param name the name for this value
	 * @param startingPath the initial folder path for the chooser widget
	 * @return the new ProjectFileValue that was defined
	 */
	public ProjectFileValue defineProjectFile(String name, String startingPath) {
		checkDup(name);
		ProjectFileValue value = new ProjectFileValue(name, startingPath);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Defines a value of type DomainFolder (folders in a Ghidra project).
	 * @param name the name for this value
	 * @return the new ProjectFolderValue that was defined
	 */
	public ProjectFolderValue defineProjectFolder(String name) {
		return defineProjectFolder(name, null);
	}

	/**
	 * Defines a value of type DomainFolder (files in a Ghidra project).
	 * @param name the name for this value
	 * @param defaultValuePath the path for the initial value (can be null)
	 * @return the new ProjectFolderValue that was defined
	 */
	public ProjectFolderValue defineProjectFolder(String name, String defaultValuePath) {
		checkDup(name);
		ProjectFolderValue value = new ProjectFolderValue(name, defaultValuePath);
		valuesMap.put(name, value);
		return value;
	}

	/**
	 * Gets the {@link Address} value for the given name.
	 * @param name the name of a previously defined Address value
	 * @return the Address
	 * @throws IllegalArgumentException if the name hasn't been defined as an Address type
	 */
	public Address getAddress(String name) {
		AddressValue addressValue = getValue(name, AddressValue.class, "Address");
		return addressValue.getValue();
	}

//==================================================================================================
// Get Value Methods
//==================================================================================================	
	/**
	 * Gets the Language ({@link LanguageCompilerSpecPair}) value for the given name.
	 * @param name the name of a previously defined language value
	 * @return the language value
	 * @throws IllegalArgumentException if the name hasn't been defined as a language type
	 */
	public LanguageCompilerSpecPair getLanguage(String name) {
		LanguageValue value = getValue(name, LanguageValue.class, "Language");
		return value.getValue();
	}

	/**
	 * Gets (opens) the {@link Program} value for the given name. If the program is already open,
	 * then the consumer will be added to the program. The caller of this method is responsible
	 * for calling {@link Program#release(Object)} with the same consumer when it is done using this
	 * program. Program are only closed after all consumers are released. If multiple calls
	 * are made to this method, then the consumer will be added multiple times and must be released
	 * multiple times.
	 * <P>
	 * The consumer can be any object, but since the consumer's purpose is to keep the program open 
	 * while some object is using it, the object itself is typically passed in as
	 * the consumer. For example, when used in a script, passing in the java keyword "this" as the
	 * consumer will make the script itself the consumer.
	 * <P>
	 * @param name the name of a previously defined program value
	 * @param consumer the consumer to be used to open the program
	 * @param tool if non-null, the program will also be opened in the given tool. Note: the
	 * program will only be added to the tool once even if this method is called multiple times.
	 * @param upgradeIfNeeded if true, program will be upgraded if needed and possible. If false,
	 * the program will only be upgraded after first prompting the user. In headless mode, it will
	 * attempt to upgrade only if the parameter is true.
	 * @return an opened program with the given consumer for the selected domain file or null if
	 * no program was selected.
	 * @throws VersionException if the Program is out-of-date from the version of GHIDRA and an 
	 * upgrade was not been performed. In non-headless mode, the user will have already been
	 * notified via a popup dialog.
	 * current Ghidra Program version.
	 * @throws IOException if there is an error accessing the Program's DomainObject
	 * @throws CancelledException if the operation is cancelled
	 * @throws IllegalArgumentException if the name hasn't been defined as a project folder type
	 */
	public Program getProgram(String name, Object consumer, Tool tool, boolean upgradeIfNeeded)
			throws VersionException, IOException, CancelledException {
		ProgramFileValue programFileValue = getValue(name, ProgramFileValue.class, "Program");
		return programFileValue.openProgram(consumer, tool, upgradeIfNeeded, monitor);
	}

	/**
	 * Gets the project file ({@link DomainFile}) value for the given name.
	 * @param name the name of a previously defined project file value
	 * @return the project file value
	 * @throws IllegalArgumentException if the name hasn't been defined as a project file type
	 */
	public DomainFile getProjectFile(String name) {
		ProjectFileValue domainFileValue = getValue(name, ProjectFileValue.class, "Domain File");
		return domainFileValue.getValue();
	}

	/**
	 * Gets the project folder ({@link DomainFolder}) value for the given name.
	 * @param name the name of a previously defined project folder value
	 * @return the project folder value
	 * @throws IllegalArgumentException if the name hasn't been defined as a project folder type
	 */
	public DomainFolder getProjectFolder(String name) {
		ProjectFolderValue domainFolderValue =
			getValue(name, ProjectFolderValue.class, "Domain Folder");
		return domainFolderValue.getValue();
	}

//==================================================================================================
// Set Value Methods
//==================================================================================================	

	/**
	 * Sets the address value for the given name.
	 * @param name the name of the Address value that was previously defined
	 * @param address the address to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as an Address type
	 */
	public void setAddress(String name, Address address) {
		AddressValue addressValue = getValue(name, AddressValue.class, "Address");
		addressValue.setValue(address);
	}

	/**
	 * Sets the Language ({@link LanguageCompilerSpecPair}) value for the given name.
	 * @param name the name of the Language value that was previously defined
	 * @param value the Language to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a Language type
	 */
	public void setLanguage(String name, LanguageCompilerSpecPair value) {
		LanguageValue languageValue = getValue(name, LanguageValue.class, "Language");
		languageValue.setValue(value);
	}

	/**
	 * Sets the {@link Program} value for the given name.
	 * @param name the name of the Program value that was previously defined
	 * @param program the Program to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a Program type
	 */
	public void setProgram(String name, Program program) {
		ProgramFileValue programFileValue = getValue(name, ProgramFileValue.class, "Program");
		programFileValue.setValue(program == null ? null : program.getDomainFile());
	}

	/**
	 * Sets the project file {@link DomainFile} value for the given name.
	 * @param name the name of the project file value that was previously defined
	 * @param file the project file to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a project file type
	 */
	public void setProjectFile(String name, DomainFile file) {
		ProjectFileValue domainFileValue = getValue(name, ProjectFileValue.class, "Domain File");
		domainFileValue.setValue(file);
	}

	/**
	 * Sets the project folder {@link DomainFolder} value for the given name.
	 * @param name the name of the project folder value that was previously defined
	 * @param folder the project folder to set as the value
	 * @throws IllegalArgumentException if the name hasn't been defined as a project folder type
	 */
	public void setProjectFolder(String name, DomainFolder folder) {
		ProjectFolderValue domainFolderValue =
			getValue(name, ProjectFolderValue.class, "Domain Folder");
		domainFolderValue.setValue(folder);
	}

}
