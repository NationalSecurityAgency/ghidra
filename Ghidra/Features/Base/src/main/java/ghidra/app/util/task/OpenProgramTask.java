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
package ghidra.app.util.task;

import java.net.URL;
import java.util.*;

import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for opening one or more programs.
 */
public class OpenProgramTask extends Task {
	private List<ProgramLocator> programsToOpen = new ArrayList<>();
	private List<OpenProgramRequest> openedPrograms = new ArrayList<>();
	private ProgramOpener programOpener;

	private final Object consumer;

	/**
	 * Construct a task for opening one or more programs.
	 * @param programLocatorList the list of program locations to open
	 * @param consumer the consumer to use for opening the programs
	 */
	public OpenProgramTask(List<ProgramLocator> programLocatorList, Object consumer) {
		super("Open Program(s)", true, false, true);
		this.consumer = consumer;
		programOpener = new ProgramOpener(consumer);
		programsToOpen.addAll(programLocatorList);
	}

	/**
	 * Construct a task for opening a program.
	 * @param locator the program location to open
	 * @param consumer the consumer to use for opening the programs
	 */
	public OpenProgramTask(ProgramLocator locator, Object consumer) {
		this(Arrays.asList(locator), consumer);
	}

	/**
	 * Construct a task for opening a program
	 * @param domainFile the {@link DomainFile} to open
	 * @param version the version to open (versions other than the current version will be
	 * opened read-only)
	 * @param consumer the consumer to use for opening the programs
	 */
	public OpenProgramTask(DomainFile domainFile, int version, Object consumer) {
		this(new ProgramLocator(domainFile, version), consumer);
	}

	/**
	 * Construct a task for opening the current version of a program
	 * @param domainFile the {@link DomainFile} to open
	 * @param consumer the consumer to use for opening the programs
	 */
	public OpenProgramTask(DomainFile domainFile, Object consumer) {
		this(new ProgramLocator(domainFile), consumer);
	}

	/**
	 * Construct a task for opening a program from a URL
	 * @param ghidraURL the URL to the program to be opened
	 * @param consumer the consumer to use for opening the programs
	 */
	public OpenProgramTask(URL ghidraURL, Object consumer) {
		this(new ProgramLocator(ghidraURL), consumer);
	}

	/**
	 * Sets the text to use for the base action type for various prompts that can appear
	 * when opening programs. (The default is "Open".) For example, you may want to override
	 * this so be something like "Open Source", or "Open target".
	 * @param text the text to use as the base action name.
	 */
	public void setOpenPromptText(String text) {
		programOpener.setPromptText(text);
	}

	/**
	 * Invoking this method prior to task execution will prevent
	 * any confirmation interaction with the user (e.g., 
	 * optional checkout, snapshot recovery, etc.).  Errors
	 * may still be displayed if they occur.
	 */
	public void setSilent() {
		programOpener.setSilent();
	}

	/**
	 * Invoking this method prior to task execution will prevent
	 * the use of optional checkout which require prompting the
	 * user.
	 */
	public void setNoCheckout() {
		programOpener.setNoCheckout();
	}

	/**
	 * Get all successful open program requests
	 * @return all successful open program requests
	 */
	public List<OpenProgramRequest> getOpenPrograms() {
		return Collections.unmodifiableList(openedPrograms);
	}

	/**
	 * Get the first successful open program request
	 * @return first successful open program request or null if none
	 */
	public OpenProgramRequest getOpenProgram() {
		if (openedPrograms.isEmpty()) {
			return null;
		}
		return openedPrograms.get(0);
	}

	@Override
	public void run(TaskMonitor monitor) {

		taskMonitor.initialize(programsToOpen.size());

		for (ProgramLocator locator : programsToOpen) {
			if (taskMonitor.isCancelled()) {
				return;
			}
			Program program = programOpener.openProgram(locator, monitor);
			if (program != null) {
				openedPrograms.add(new OpenProgramRequest(program, locator, consumer));
			}
			taskMonitor.incrementProgress(1);
		}
	}

}
