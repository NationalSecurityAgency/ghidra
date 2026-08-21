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
package ghidra.features.base.replace.handler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.RenameMemoryBlockQuickFix;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for memory block names.
 */

public class MemoryBlockSearchAndReplaceHandler extends SearchAndReplaceHandler {

	public MemoryBlockSearchAndReplaceHandler() {
		addType(new SearchType(this, "Memory Blocks", "Search and replace memory block names"));
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();
		monitor.initialize(blocks.length, "Searching MemoryBlocks...");

		Pattern pattern = query.getSearchPattern();

		for (MemoryBlock block : blocks) {
			monitor.increment();
			Matcher matcher = pattern.matcher(block.getName());
			if (matcher.find()) {
				String newName = matcher.replaceAll(query.getReplacementText());
				RenameMemoryBlockQuickFix item =
					new RenameMemoryBlockQuickFix(program, block, newName);
				accumulator.add(item);
			}

		}

	}
}
