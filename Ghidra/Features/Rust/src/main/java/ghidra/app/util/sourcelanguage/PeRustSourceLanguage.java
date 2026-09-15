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

import java.io.IOException;

import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The PE Rust {@link SourceLanguage} class
 */
public class PeRustSourceLanguage extends RustSourceLanguage {

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!program.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			return false;
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(".rdata") &&
				isRust(program, block, monitor)) {
				return true;
			}
		}
		return false;
	}
}
