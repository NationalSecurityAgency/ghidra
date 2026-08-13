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
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.info.ElfComment;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The Elf Rust {@link SourceLanguage} class
 */
public class ElfRustSourceLanguage extends RustSourceLanguage {

	private static final Pattern ELF_COMMENT_REGEX = Pattern.compile("^rustc version .*$");

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!program.getExecutableFormat().equals(ElfLoader.ELF_NAME)) {
			return false;
		}

		// ELF binaries can contain a ".comment" section that records the toolchains that
		// produced the binary.  Search this first as its quick and easy. 
		ElfComment elfComments = ElfComment.fromProgram(program);
		if (elfComments != null) {
			for (String s : elfComments.getCommentStrings()) {
				if (ELF_COMMENT_REGEX.matcher(s).matches()) {
					return true;
				}
			}
		}

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(ElfSectionHeaderConstants.dot_rodata) &&
				isRust(program, block, monitor)) {
				return true;
			}
		}
		return false;
	}
}
