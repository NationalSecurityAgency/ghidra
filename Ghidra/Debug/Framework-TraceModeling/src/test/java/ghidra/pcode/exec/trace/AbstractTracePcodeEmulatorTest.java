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
package ghidra.pcode.exec.trace;

import java.util.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Instruction;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

public class AbstractTracePcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {

	public TraceThread initTrace(ToyDBTraceBuilder tb, String stateInit,
			List<String> assembly) throws Throwable {
		return initTrace(tb, tb.range(0x00400000, 0x0040ffff), tb.range(0x00100000, 0x0010ffff),
			stateInit, assembly);
	}

	/**
	 * Build a trace with a program ready for emulation
	 * 
	 * <p>
	 * This creates a relatively bare-bones trace with initial state for testing trace
	 * emulation/interpolation. It adds ".text" and "stack" regions, creates a thread, assembles
	 * given instructions, and then executes the given Sleigh source (in the context of the new
	 * thread) to finish initializing the trace. Note, though given first, the Sleigh is executed
	 * after assembly. Thus, it can be used to modify the resulting machine code by modifying the
	 * memory where it was assembled.
	 * 
	 * @param tb the trace builder
	 * @param stateInit Sleigh source to execute to initialize the trace state before emulation
	 * @param assembly lines of assembly to place starting at {@code 0x00400000}
	 * @return a new trace thread, whose register state is initialized as specified
	 * @throws Throwable if anything goes wrong
	 */
	public TraceThread initTrace(ToyDBTraceBuilder tb, AddressRange text, AddressRange stack,
			String stateInit, List<String> assembly) throws Throwable {
		TraceMemoryManager mm = tb.trace.getMemoryManager();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread1", 0);
			mm.addRegion("Regions[bin:.text]", Lifespan.nowOn(0), text,
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			mm.addRegion("Regions[stack1]", Lifespan.nowOn(0), stack,
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			Iterator<Instruction> block = assembly.isEmpty() ? Collections.emptyIterator()
					: asm.assemble(text.getMinAddress(), assembly.toArray(String[]::new));
			Instruction last = null;
			while (block.hasNext()) {
				last = block.next();
			}
			Msg.info(this, "Assembly ended at: " + (last == null ? "null" : last.getMaxAddress()));
			if (!stateInit.isEmpty()) {
				PcodeExecutor<byte[]> exec =
					TraceSleighUtils.buildByteExecutor(tb.trace, 0, thread, 0);
				PcodeProgram initProg = SleighProgramCompiler.compileProgram(
					(SleighLanguage) tb.language, "test", stateInit,
					PcodeUseropLibrary.nil());
				exec.execute(initProg, PcodeUseropLibrary.nil());
			}
		}
		return thread;
	}

}
