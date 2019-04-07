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

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

public class MergeTestFacilitator {

	private TestEnv env;
	private AbstractMTFModel model;

	public MergeTestFacilitator() throws IOException {
		env = new TestEnv();
	}

	public void initialize(String programName, ProgramModifierListener modifier) throws Exception {
		if (model != null) {
			throw new AssertException("Initialize was called more than once!");
		}

		model = new RealProgramMTFModel(env);
		model.initialize(programName, modifier);
	}

	public void initialize(String programName, OriginalProgramModifierListener modifier)
			throws Exception {
		if (model != null) {
			throw new AssertException("Initialize was called more than once!");
		}

		model = new RealProgramMTFModel(env);
		model.initialize(programName, modifier);
	}

	/**
	 * This version of initialize allows you to write tests that use an in-memory version
	 * of {@link Program}, which will make the tests faster.  Plus, the interface of
	 * {@link MergeProgramModifier} is stubbed-out for you, meaning less code.  Plus, plus,
	 * the callback for this method passes you a {@link MergeProgram}, which has a simpler
	 * interface for configuring your merge tests.
	 *  
	 * @param programName the name of the program--can be anything
	 * @param modifier your implementation of the callback, with overridden methods for
	 *                 things you wish to configure.
	 * @throws Exception if there is any problem
	 */
	public void initialize(String programName, MergeProgramModifier modifier) throws Exception {
		if (model != null) {
			throw new AssertException("Initialize was called more than once!");
		}

		model = new InMemoryProgramMTFModel(env);
		model.initialize(programName, modifier);
	}

	static DomainFile copyDatabaseDomainFile(DomainFile df, String newName)
			throws IOException, InvalidNameException, CancelledException {
		return AbstractMTFModel.copyDatabaseDomainFile(df, newName);
	}

	/**
	 * Get the change set for the Private program.
	 */
	public ProgramChangeSet getPrivateChangeSet() {
		return model.getPrivateChangeSet();
	}

	/**
	 * Get the change set for Result program.
	 */
	public ProgramChangeSet getResultChangeSet() {
		return model.getResultChangeSet();
	}

	public void dispose() {
		if (model != null) {
			model.dispose();
		}
		else {
			// the model usually does this, but there is no model
			env.dispose();
		}
	}

	public TestEnv getTestEnvironment() {
		return env;
	}

	/**
	 * Returns original Immutable program.
	 * This represents the original checked-out version.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 */
	public ProgramDB getOriginalProgram() {
		if (model == null) {
			return null; // initialize was never called
		}
		return model.getOriginalProgram();
	}

	/**
	 * Returns latest Immutable program.
	 * This represents the current version.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 */
	public ProgramDB getLatestProgram() {
		if (model == null) {
			return null; // initialize was never called
		}
		return model.getLatestProgram();
	}

	/**
	 * Returns private Immutable program.
	 * This represents the local program to be checked-in.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 */
	public ProgramDB getPrivateProgram() {
		if (model == null) {
			return null; // initialize was never called
		}
		return model.getPrivateProgram();
	}

	/**
	 * Returns results program for update.
	 * This represents the checkin program containing the merged data.
	 * Program returned will be released by the MergeTestFacilitator 
	 * when disposed or re-initialized.
	 */
	public ProgramDB getResultProgram() {
		if (model == null) {
			return null; // initialize was never called
		}
		return model.getResultProgram();
	}

}
