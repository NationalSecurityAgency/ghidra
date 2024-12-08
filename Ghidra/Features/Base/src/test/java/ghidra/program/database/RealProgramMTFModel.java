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

import db.Transaction;
import ghidra.test.TestEnv;
import ghidra.util.TestUniversalIdGenerator;
import ghidra.util.exception.AssertException;

/**
 * The non-preferred way of configuring tests for merge testing, which is to use real
 * programs that are files on disk.  You should try to use the
 * {@link InMemoryProgramMTFModel} by using 
 * {@link MergeTestFacilitator#initialize(String, MergeProgramModifier)} when writing
 * merge tests.
 */
// TODO rename--this is no longer using real programs
public class RealProgramMTFModel extends AbstractMTFModel {

	// Use simple ID generation
	private TestUniversalIdGenerator universalIdGenerator = new TestUniversalIdGenerator();

	RealProgramMTFModel(TestEnv env) {
		super(env);
	}

	@Override
	public void initialize(String programName, ProgramModifierListener modifier) throws Exception {
		cleanup();

		MergeProgramGenerator programGenerator = createProgramGenerator(programName);
		originalProgram = programGenerator.generateProgram(programName);

		latestProgram = cloneProgram(originalProgram, this);
		try (Transaction tx = latestProgram.openTransaction("Modify Latest Program")){
			modifier.modifyLatest(latestProgram);
		}

		resultProgram = cloneProgram(latestProgram, this);

		privateProgram = cloneProgram(originalProgram, this);
		try (Transaction tx = privateProgram.openTransaction("Modify Private Program")){
			modifier.modifyPrivate(privateProgram);
		}
		recordChanges();
		clearChanges();
	}

	@Override
	public void initialize(String programName, OriginalProgramModifierListener modifier)
			throws Exception {
		cleanup();

		MergeProgramGenerator programGenerator = createProgramGenerator(programName);
		originalProgram = programGenerator.generateProgram(programName);
		try (Transaction tx = originalProgram.openTransaction("Modify Original Program")){
			modifier.modifyOriginal(originalProgram);
		}

		privateProgram = cloneProgram(originalProgram, this);
		try (Transaction tx = privateProgram.openTransaction("Modify Private Program")){
			modifier.modifyPrivate(privateProgram);
		}

		latestProgram = cloneProgram(originalProgram, this);
		try (Transaction tx = latestProgram.openTransaction("Modify Latest Program")){
			modifier.modifyLatest(latestProgram);
		}

		resultProgram = cloneProgram(latestProgram, this);

		recordChanges();
		clearChanges();
	}

	private MergeProgramGenerator createProgramGenerator(String programName) {
		if (programName.toLowerCase().contains("notepad")) {
			return new MergeProgramGenerator_Notepads(this);
		}
		else if (programName.toLowerCase().contains("calc")) {
			return new MergeProgramGenerator_Calcs(this);
		}
		else if (programName.toLowerCase().contains("difftest")) {
			return new MergeProgramGenerator_DiffTestPrograms(this);
		}
		else if (programName.toLowerCase().contains("r4000")) {
			return new MergeProgramGenerator_Mips(this);
		}
		else if (programName.toLowerCase().contains("wallace")) {
			return new MergeProgramGenerator_Wallace(this);
		}
		throw new AssertException("Add new program generator for program: " + programName);
	}

	@Override
	public void initialize(String programName, MergeProgramModifier modifier) {
		throw new UnsupportedOperationException();
	}

	private void recordChanges() {
		// ...keep track of the changes we've made
		latestChangeSet = latestProgram.getChanges();
		privateChangeSet = privateProgram.getChanges();
	}

	private void clearChanges() {

		// trick each program to think that it hasn't been changed so that the merge process 
		// ignores all the work done so far
		latestProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));
		resultProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));
		privateProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));
		originalProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));
	}
}
