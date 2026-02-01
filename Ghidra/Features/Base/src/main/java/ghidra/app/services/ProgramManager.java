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
package ghidra.app.services;

import java.net.URL;

import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Service for managing programs. Multiple programs may be open in a tool, but only one is active at
 * any given time.
 */
@ServiceInfo(
		defaultProvider = ProgramManagerPlugin.class,
		description = "Get the currently open program")
public interface ProgramManager {

	/**
	 * Program will be open in a Hidden state if not already open. This mode is generally used in
	 * conjunction with a persistent program owner.
	 */
	public static final int OPEN_HIDDEN = 0;

	/**
	 * Program will be open as the currently active program within the tool.
	 */
	public static final int OPEN_CURRENT = 1;

	/**
	 * Program will be open within the tool but no change will be made to the currently active
	 * program. If this is the only program open, it will become the currently active program.
	 */
	public static final int OPEN_VISIBLE = 2;

	/**
	 * Return the program that is currently active.
	 *
	 * @return may return null if no program is open
	 */
	public Program getCurrentProgram();

	/**
	 * Returns true if the specified program is open and considered visible to the user.
	 *
	 * @param program the program
	 * @return true if the specified program is open and considered visible to the user
	 */
	public boolean isVisible(Program program);

	/**
	 * Closes the currently active program
	 *
	 * @return true if the close is successful. false if the close fails or if there is no program
	 *         currently active.
	 */
	public boolean closeProgram();

	/**
	 * Open the program corresponding to the given url.
	 *
	 * @param ghidraURL valid server-based program URL
	 * @param state initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
	 *            states will be ignored if the program is already open.
	 * @return the opened program or null if the user canceled the "open" or an error occurred
	 * @see GhidraURL
	 */
	public Program openProgram(URL ghidraURL, int state);

	/**
	 * Open the program for the given domainFile. Once open it will become the active program.
	 *
	 * @param domainFile domain file that has the program
	 * @return the opened program or null if the user canceled the "open" or an error occurred
	 */
	public Program openProgram(DomainFile domainFile);

	/**
	 * Opens a program or retrieves it from a cache. If the program is in the cache, the consumer
	 * will be added the program before returning it. Otherwise, the program will be opened with
	 * the consumer. In addition, opening or accessing a cached program, will guarantee that it will
	 * remain open for period of time, even if the caller of this method releases it from the 
	 * consumer that was passed in. If the program isn't accessed again, it will be eventually be
	 * released from the cache. If the program is still in use when the timer expires, the
	 * program will remain in the cache with a new full expiration time. Calling this method
	 * does not open the program in the tool.
	 * 
	 * @param domainFile the DomainFile from which to open a program.
	 * @param consumer the consumer that is using the program. The caller is responsible for
	 * releasing (See {@link Program#release(Object)}) the consumer when done with the program.
	 * @return the program for the given domainFile or null if unable to open the program
	 */
	public Program openCachedProgram(DomainFile domainFile, Object consumer);

	/**
	 * Opens a program or retrieves it from a cache. If the program is in the cache, the consumer
	 * will be added the program before returning it. Otherwise, the program will be opened with
	 * the consumer. In addition, opening or accessing a cached program, will guarantee that it will
	 * remain open for period of time, even if the caller of this method releases it from the 
	 * consumer that was passed in. If the program isn't accessed again, it will be eventually be
	 * released from the cache. If the program is still in use when the timer expires, the
	 * program will remain in the cache with a new full expiration time.  Calling this method
	 * does not open the program in the tool.
	 * 
	 * @param ghidraURL the ghidra URL from which to open a program.
	 * @param consumer the consumer that is using the program. The caller is responsible for
	 * releasing (See {@link Program#release(Object)}) the consumer when done with the program.
	 * @return the program for the given URL or null if unable to open the program
	 */
	public Program openCachedProgram(URL ghidraURL, Object consumer);

	/**
	 * Opens the specified version of the program represented by the given DomainFile. This method
	 * should be used for shared DomainFiles. The newly opened file will be made the active program.
	 *
	 * @param df the DomainFile to open
	 * @param version the version of the Program to open
	 * @return the opened program or null if the user canceled the "open" or an error occurred
	 */
	public Program openProgram(DomainFile df, int version);

	/**
	 * Open the program for the given domainFile
	 *
	 * @param domainFile domain file that has the program
	 * @param version the version of the Program to open. Specify DomainFile.DEFAULT_VERSION for
	 *            file update mode.
	 * @param state initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
	 *            states will be ignored if the program is already open.
	 * @return the opened program or null if the user canceled the "open" or an error occurred
	 */
	public Program openProgram(DomainFile domainFile, int version, int state);

	/**
	 * Opens the program to the tool. In this case the program is already open, but this tool may
	 * not have it registered as open. The program is made the active program.
	 *
	 * @param program the program to register as open with the tool.
	 */
	public void openProgram(Program program);

	/**
	 * Open the specified program in the tool.
	 *
	 * @param program the program
	 * @param state initial open state (OPEN_HIDDEN, OPEN_CURRENT, OPEN_VISIBLE). The visibility
	 *            states will be ignored if the program is already open.
	 */
	public void openProgram(Program program, int state);

	/**
	 * Saves the current program, possibly prompting the user for a new name.
	 */
	public void saveProgram();

	/**
	 * Saves the specified program, possibly prompting the user for a new name.
	 *
	 * @param program the program
	 */
	public void saveProgram(Program program);

	/**
	 * Prompts the user to save the current program to a selected file.
	 */
	public void saveProgramAs();

	/**
	 * Prompts the user to save the specified program to a selected file.
	 *
	 * @param program the program
	 */
	public void saveProgramAs(Program program);

	/**
	 * Establish a persistent owner on an open program. This will cause the program manager to imply
	 * make a program hidden if it is closed.
	 *
	 * @param program the program
	 * @param owner the owner
	 * @return true if program is open and another object is not already the owner, or the specified
	 *         owner is already the owner.
	 * @see #releaseProgram(Program, Object)
	 * @deprecated this method is no longer used by the system
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public boolean setPersistentOwner(Program program, Object owner);

	/**
	 * Release the persistent ownership of a program.
	 * <p>
	 * The program will automatically be closed if it is hidden or was marked as temporary. If any
	 * of these closures corresponds to a program with changes the user will be given an opportunity
	 * to save or keep the program open.
	 * <p>
	 * If persistentOwner is not the correct owner, the method will have no affect.
	 *
	 * @param program the program
	 * @param persistentOwner the owner defined by {@link #setPersistentOwner(Program, Object)}
	 * @deprecated this method is no longer used by the system
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	public void releaseProgram(Program program, Object persistentOwner);

	/**
	 * Closes the given program with the option of saving any changes. The exact behavior of this
	 * method depends on several factors. First of all, if any other tool has this program open,
	 * then the program is closed for this tool only and the user is not prompted to save the
	 * program regardless of the ignoreChanges flag. Otherwise, if ignoreChanges is false and
	 * changes have been made, the user is prompted to save the program.
	 *
	 * @param program the program to close.
	 * @param ignoreChanges if true, the program is closed without saving any changes.
	 * @return true if the program was closed. Returns false if the user canceled the close while
	 *         being prompted to save. Also returns false if the program passed in as a parameter is
	 *         null.
	 */
	boolean closeProgram(Program program, boolean ignoreChanges);

	/**
	 * Closes all open programs in this tool except the current program. If this tool is the only
	 * tool with a program open and that program has changes, then the user will be prompted to
	 * close each such file. (Providing the ignoreChanges flag is false)
	 *
	 * @param ignoreChanges if true, the programs will be closed without saving changes.
	 * @return true if all other programs were closed. Returns false if the user canceled the close
	 *         while being prompted to save.
	 */
	public boolean closeOtherPrograms(boolean ignoreChanges);

	/**
	 * Closes all open programs in this tool. If this tool is the only tool with a program open and
	 * that program has changes, then the user will be prompted to close each such file. (Providing
	 * the ignoreChanges flag is false)
	 *
	 * @param ignoreChanges if true, the programs will be closed without saving changes.
	 * @return true if all programs were closed. Returns false if the user canceled the close while
	 *         being prompted to save.
	 */
	public boolean closeAllPrograms(boolean ignoreChanges);

	/**
	 * Sets the given program to be the current active program in the tool.
	 *
	 * @param p the program to make active.
	 */
	public void setCurrentProgram(Program p);

	/**
	 * Returns the first program in the list of open programs that contains the given address.
	 * Programs are searched in the order they were opened within a given priority. Program are
	 * initially opened with the PRIORITY_NORMAL priority, but can be set to have PRIORITY_HIGH or
	 * PRIORITY_LOW.
	 *
	 * @param addr the address for which to search.
	 * @return the first program that can be found to contain the given address.
	 */
	public Program getProgram(Address addr);

	/**
	 * Returns a list of all open program.
	 *
	 * @return the programs
	 */
	public Program[] getAllOpenPrograms();

}
