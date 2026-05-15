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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Marks memory blocks at ram:0x80000000+ as volatile so the decompiler treats them
 * as MMIO with side effects.  NDS32 chips put peripheral MMIO in the upper half of
 * the address space, but the pspec schema has no {@code volatile} attribute on
 * {@code <memory_block>}, so this analyzer applies the flag after import.
 */
public class NDS32VolatileBlockAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 Volatile MMIO Blocks";
	private static final String DESCRIPTION =
		"Marks memory blocks at ram:0x80000000+ as volatile so the " +
			"decompiler treats them as MMIO with side effects.";
	private static final String PROCESSOR_NAME = "NDS32";
	private static final long MMIO_THRESHOLD = 0x80000000L;

	public NDS32VolatileBlockAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(true);
		// Run before constant propagation so loads/stores stay opaque.
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		Memory mem = program.getMemory();
		int changed = 0;
		for (MemoryBlock b : mem.getBlocks()) {
			if (b.isVolatile()) {
				continue;
			}
			if (!"ram".equals(b.getStart().getAddressSpace().getName())) {
				continue;
			}
			if (Long.compareUnsigned(b.getStart().getOffset(), MMIO_THRESHOLD) < 0) {
				continue;
			}
			b.setVolatile(true);
			changed++;
		}
		if (changed > 0) {
			Msg.info(this, NAME + ": Marked " + changed + " MMIO block(s) volatile.");
		}
		return changed > 0;
	}
}
