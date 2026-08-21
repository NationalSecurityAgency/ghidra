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
package ghidra.feature.vt.gui.wizard.session;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Wizard data used by the {@link VTNewSessionWizardModel} and its steps for the "create new version
 * tracking session" wizard.
 */
public class NewSessionData {
	private Program sourceProgram;
	private Program destinationProgram;
	private DomainFile sourceFile;
	private DomainFile destinationFile;
	private DomainFolder sessionFolder;
	private String sessionName;
	private boolean preconditionChecksCompleted;

	public DomainFile getSourceFile() {
		return sourceFile;
	}

	public DomainFile getDestinationFile() {
		return destinationFile;
	}

	public Program getSourceProgram() {
		return sourceProgram;
	}

	public Program getDestinationProgram() {
		return destinationProgram;
	}

	public String getSessionName() {
		return sessionName;
	}

	public DomainFolder getSessionFolder() {
		return sessionFolder;
	}

	public void setSourceFile(DomainFile file, PluginTool tool) {
		this.sourceFile = file;
		if (isProgramInvalidForFile(file, sourceProgram)) {
			sourceProgram.release(tool);
			sourceProgram = null;
		}
	}

	private boolean isProgramInvalidForFile(DomainFile file, Program program) {

		if (program == null) {
			return false;
		}
		if (program.getDomainFile().equals(file)) {
			return false;
		}
		return true;
	}

	public void setDestinationFile(DomainFile file, PluginTool tool) {
		this.destinationFile = file;
		if (isProgramInvalidForFile(file, destinationProgram)) {
			sourceProgram.release(tool);
			sourceProgram = null;
		}
	}

	public void setSourceProgram(Program program) {
		this.sourceProgram = program;
		preconditionChecksCompleted = false;
	}

	public void setDestinationProgram(Program program) {
		this.destinationProgram = program;
		preconditionChecksCompleted = false;
	}

	public void setSessionName(String name) {
		this.sessionName = name;
	}

	public void setSessionFolder(DomainFolder folder) {
		this.sessionFolder = folder;
	}

	public boolean hasPerformedPreconditionChecks() {
		return preconditionChecksCompleted;
	}

	public void setPerformedPreconditionChecks(boolean b) {
		preconditionChecksCompleted = b;
	}
}
