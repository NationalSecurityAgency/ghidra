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
package ghidra.program.database;

import java.io.IOException;

import db.buffers.BufferFile;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.data.GhidraFolder;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This model is used by the {@link MergeTestFacilitator} to configure programs needed 
 * for testing.
 */
public abstract class AbstractMTFModel {

	protected TestEnv env;
	protected ProgramDB originalProgram;
	protected ProgramDB latestProgram;
	protected ProgramDB privateProgram;
	protected ProgramDB resultProgram;
	protected ProgramChangeSet privateChangeSet; // change set from private program
	protected ProgramChangeSet latestChangeSet; // change set from latest program

	AbstractMTFModel(TestEnv env) {
		this.env = env;
	}

	public void dispose() {
		try {
			cleanup();
		}
		finally {
			env.dispose();
		}
	}

	/**
	 * Returns original Immutable program.
	 * This represents the original checked-out version.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 * @return the program
	 */
	public ProgramDB getOriginalProgram() {
		return originalProgram;
	}

	/**
	 * Returns latest Immutable program.
	 * This represents the current version.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 * @return the program
	 */
	public ProgramDB getLatestProgram() {
		return latestProgram;
	}

	/**
	 * Returns private Immutable program.
	 * This represents the local program to be checked-in.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 * @return the program
	 */
	public ProgramDB getPrivateProgram() {
		return privateProgram;
	}

	/**
	 * Returns results program for update.
	 * This represents the checkin program containing the merged data.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 * @return the program
	 */
	public ProgramDB getResultProgram() {
		return resultProgram;
	}

	public ProgramChangeSet getPrivateChangeSet() {
		return privateChangeSet;
	}

	public ProgramChangeSet getResultChangeSet() {
		return latestChangeSet;
	}

	public TestEnv getTestEnvironment() {
		return env;
	}

	protected void disableAutoAnalysis(Program p) {
		// Disable all analysis
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(p);
		AbstractGenericTest.setInstanceField("isEnabled", analysisMgr, Boolean.FALSE);
	}

	static DomainFile copyDatabaseDomainFile(DomainFile df, String newName) throws IOException,
			InvalidNameException, CancelledException {
		FileSystem fileSystem = (FileSystem) AbstractGenericTest.getInstanceField("fileSystem", df);

		GhidraFolder parent = (GhidraFolder) df.getParent();
		DatabaseItem item = (DatabaseItem) fileSystem.getItem(parent.getPathname(), df.getName());

		BufferFile bufferFile = item.open();
		try {
			fileSystem.createDatabase(parent.getPathname(), newName, FileIDFactory.createFileID(),
				bufferFile, null, item.getContentType(), false, TaskMonitor.DUMMY,
				null);
		}
		finally {
			bufferFile.dispose();
		}

		AbstractGenericTest.invokeInstanceMethod("refreshFolderData", parent);
		return parent.getFile(newName);
	}

	protected void cleanup() {

		if (originalProgram != null) {
			originalProgram.release(this);
			originalProgram = null;
		}
		if (latestProgram != null) {
			latestProgram.release(this);
			latestProgram = null;
		}
		if (privateProgram != null) {
			privateProgram.release(this);
			privateProgram = null;
		}
		if (resultProgram != null) {
			resultProgram.flushEvents();
			AbstractGenericTest.waitForSwing();
			resultProgram.release(this);
			resultProgram = null;
		}
	}

	public abstract void initialize(String programName, MergeProgramModifier modifier)
			throws Exception;

	public abstract void initialize(String programName, OriginalProgramModifierListener l)
			throws Exception;

	public abstract void initialize(String programName, ProgramModifierListener l) throws Exception;
}
