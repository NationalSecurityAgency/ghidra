/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.test.TestEnv;

/**
 * A version of the {@link AbstractMTFModel} that allows test writers to use an 
 * in-memory program, instead of one that is a real program, loaded from a file on disk.
 */
public class InMemoryProgramMTFModel extends AbstractMTFModel {

	InMemoryProgramMTFModel(TestEnv env) {
		super(env);
	}

	@Override
	public void initialize(String programName, OriginalProgramModifierListener l) throws Exception {
		throw new UnsupportedOperationException();
	}

	@Override
	public void initialize(String programName, ProgramModifierListener l) throws Exception {
		throw new UnsupportedOperationException();
	}

	@Override
	public void initialize(String programName, MergeProgramModifier modifier) throws Exception {
		cleanup();

		MergeProgramBuilder builder =
			new MergeProgramBuilder(programName, ProgramBuilder._TOY, this);

		MergeProgram mp = builder.createAllMergeProgram();
		modifier.initializeProgram(mp);

		privateProgram = builder.getPrivateProgram();
		disableAutoAnalysis(privateProgram);

		originalProgram = builder.getOriginalProgram();

		// TODO?
		// Make copy while preserving Database-ID 

		resultProgram = builder.getResultProgram();
		disableAutoAnalysis(resultProgram);

		modifier.modifyLatest(builder.createLatestMergeProgram());
		latestChangeSet = resultProgram.getChanges();
		resultProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));

		latestProgram = builder.getLatestProgram();
		latestProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));

		modifier.modifyPrivate(builder.createPrivateMergeProgram());
		privateChangeSet = privateProgram.getChanges();
		privateProgram.setChangeSet(new ProgramDBChangeSet(resultProgram.getAddressMap(), 20));
	}

}
