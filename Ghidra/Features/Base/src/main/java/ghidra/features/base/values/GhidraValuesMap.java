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

import docking.Tool;
import docking.widgets.values.GValuesMap;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;

/**
 * Extends GValuesMap to add Ghidra specific types such as Address and Program
 */
public class GhidraValuesMap extends GValuesMap {

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
	 * Defines a value of type Program. This method opens programs using the given
	 * consumer and must be properly released when it is no longer needed. This is true
	 * even if the program is also opened in the tool.
	 * @param name the name for this value
	 * @param consumer the consumer to be used to open the program
	 * @param tool if non-null, the program will also be opened in the given tool
	 * @return the user-selected Program if a program was 
	 * not selected or null.  NOTE: It is very important that the program instance
	 * returned by this method ALWAYS be properly released from the consumer when no 
	 * longer needed  (i.e., {@code program.release(consumer) } - failure to 
	 * properly release the program may result in improper project disposal.  If the program was 
	 * also opened in the tool, the tool will be a second consumer responsible for its 
	 * own release.
	 */
	public ProgramValue defineProgram(String name, Object consumer, Tool tool) {
		return defineProgram(name, null, consumer, tool);
	}

	/**
	 * Defines a value of type Program.
	 * @param name the name for this value
	 * @param defaultValue the initial value
	 * @param consumer the consumer to be used to open the program
	 * @param tool if non-null, the program will also be opened in the given tool
	 * @return the new ProgramValue that was defined
	 */
	public ProgramValue defineProgram(String name, Program defaultValue, Object consumer,
			Tool tool) {
		checkDup(name);
		ProgramValue value = new ProgramValue(name, defaultValue, consumer, tool);
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
	 * @param defaultValue the initial value
	 * @return the new ProjectFileValue that was defined
	 */
	public ProjectFileValue defineProjectFile(String name, DomainFile defaultValue) {
		checkDup(name);
		ProjectFileValue value = new ProjectFileValue(name, defaultValue);
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
	 * @param defaultValue the initial value (can be null)
	 * @return the new ProjectFolderValue that was defined
	 */
	public ProjectFolderValue defineProjectFolder(String name, DomainFolder defaultValue) {
		checkDup(name);
		ProjectFolderValue value = new ProjectFolderValue(name, defaultValue);
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
	 * Gets the {@link Program} value for the given name.
	 * @param name the name of a previously defined project folder value
	 * @return the project folder value
	 * @throws IllegalArgumentException if the name hasn't been defined as a project folder type
	 */
	public Program getProgram(String name) {
		ProgramValue programValue = getValue(name, ProgramValue.class, "Program");
		return programValue.getValue();
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
		ProgramValue programValue = getValue(name, ProgramValue.class, "Program");
		programValue.setValue(program);
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
