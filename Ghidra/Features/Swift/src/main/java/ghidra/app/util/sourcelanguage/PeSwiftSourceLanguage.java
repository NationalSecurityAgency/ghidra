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
package ghidra.app.util.sourcelanguage;

import java.util.Arrays;

import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * The PE Swift {@link SourceLanguage} class
 */
public class PeSwiftSourceLanguage extends SwiftSourceLanguage {

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor) {
		if (!program.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			return false;
		}
		return Arrays.stream(program.getMemory().getBlocks())
				.map(MemoryBlock::getName)
				.anyMatch(name -> name.startsWith(".sw5"));
	}
}
