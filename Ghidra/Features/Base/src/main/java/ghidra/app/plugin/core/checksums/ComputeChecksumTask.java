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
package ghidra.app.plugin.core.checksums;

import java.util.List;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ComputeChecksumTask extends Task {

	private ComputeChecksumsProvider provider;
	private Memory memory;
	private AddressSetView set;
	private String errorMessage;

	public ComputeChecksumTask(ComputeChecksumsProvider provider, Memory memory,
			AddressSetView set) {
		super("Generating Checksums", true, true, true);
		this.provider = provider;
		this.memory = memory;
		this.set = set;

		if (set == null) {
			return;
		}

		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isInitialized()) {
				continue;
			}

			if (set.intersects(block.getStart(), block.getEnd())) {
				errorMessage = "The current selection contains uninitialized memory. " +
					"This memory is excluded from the checksum.";
				break;
			}
		}
	}

	@Override
	public void run(TaskMonitor monitor) {

		AddressSet addrs = new AddressSet(set != null ? set : memory);
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) {
				addrs.deleteRange(block.getStart(), block.getEnd());
			}
		}

		List<ChecksumAlgorithm> checksumAlgorithms = provider.getChecksums();
		monitor.initialize(checksumAlgorithms.size());
		for (ChecksumAlgorithm check : checksumAlgorithms) {
			monitor.setMessage("Generating " + check.getName() + " checksum...");
			try {
				check.updateChecksum(memory, addrs, monitor, provider);
			}
			catch (MemoryAccessException | CancelledException e) {
				check.reset();
			}
			monitor.incrementProgress(1);
		}

		SystemUtilities.runSwingLater(() -> {
			provider.generateChecksumCompleted();
		});
	}

	boolean hasError() {
		return errorMessage != null;
	}

	String getErrorMessage() {
		return errorMessage;
	}
}
