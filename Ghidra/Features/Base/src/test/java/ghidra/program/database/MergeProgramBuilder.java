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

import java.util.*;

import ghidra.framework.options.Options;

public class MergeProgramBuilder {

	private ProgramBuilder privateBuilder;
	private ProgramBuilder latestBuilder;
	private ProgramBuilder resultBuilder;
	private ProgramBuilder originalBuilder;

	private Set<ProgramBuilder> builders = new HashSet<ProgramBuilder>();

	public MergeProgramBuilder(String name, String languageString, Object consumer)
			throws Exception {
		privateBuilder = new ProgramBuilder(name, languageString, consumer);
		builders.add(privateBuilder);
		latestBuilder = new ProgramBuilder(name, languageString, consumer);
		builders.add(latestBuilder);
		resultBuilder = new ProgramBuilder(name, languageString, consumer);
		builders.add(resultBuilder);
		originalBuilder = new ProgramBuilder(name, languageString, consumer);
		builders.add(originalBuilder);

		initialize();
	}

	private void initialize() {

		Date date = new Date();
		for (ProgramBuilder builder : builders) {
			ProgramDB p = builder.getProgram();
			int ID = p.startTransaction("Property");
			Options options = p.getOptions("Program Information");
			options.setDate("Date Created", date);
			p.endTransaction(ID, true);

			builder.setRecordChanges(true);
		}

	}

	public ProgramDB getLatestProgram() {
		return latestBuilder.getProgram();
	}

	public ProgramDB getPrivateProgram() {
		return privateBuilder.getProgram();
	}

	public ProgramDB getResultProgram() {
		return resultBuilder.getProgram();
	}

	public ProgramDB getOriginalProgram() {
		return originalBuilder.getProgram();
	}

	public void setBookmark(String address, String bookmarkType, String category, String comment) {

		for (ProgramBuilder builder : builders) {
			builder.createBookmark(address, bookmarkType, category, comment);
		}
	}

	public MergeProgram createAllMergeProgram() {
		return new MergeProgram(latestBuilder.getProgram(), privateBuilder.getProgram(),
			resultBuilder.getProgram(), originalBuilder.getProgram());
	}

	public MergeProgram createLatestMergeProgram() {
		return new MergeProgram(resultBuilder.getProgram(), latestBuilder.getProgram());
	}

	public MergeProgram createPrivateMergeProgram() {
		return new MergeProgram(privateBuilder.getProgram());
	}
}
