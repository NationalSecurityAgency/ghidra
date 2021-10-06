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
package agent.gdb.manager.impl.cmd;

import java.nio.ByteBuffer;
import java.util.List;

import com.google.common.collect.*;

import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.GdbPendingCommand;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * Implementation of {@link GdbThread#readMemory(long, ByteBuffer, int)}
 */
public class GdbReadMemoryCommand extends AbstractGdbCommandWithThreadId<RangeSet<Long>> {

	private final long addr;
	private final ByteBuffer buf;
	private final int len;

	public GdbReadMemoryCommand(GdbManagerImpl manager, Integer threadId, long addr, ByteBuffer buf,
			int len) {
		super(manager, threadId);
		this.addr = addr;
		this.buf = buf;
		this.len = len;
	}

	@Override
	protected String encode(String threadPart) {
		return "-data-read-memory-bytes" + threadPart + " 0x" + Long.toHexString(addr) + " " + len;
	}

	@Override
	public RangeSet<Long> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		List<GdbMiFieldList> rangeList = done.assumeMemoryContentsList();
		RangeSet<Long> rangeSet = TreeRangeSet.create();
		int pos = buf.position();
		int max = pos;
		for (GdbMiFieldList r : rangeList) {
			long begin = GdbParsingUtils.parsePrefixedHex(r.getString("begin"));
			long offset = GdbParsingUtils.parsePrefixedHex(r.getString("offset"));
			long end = GdbParsingUtils.parsePrefixedHex(r.getString("end"));
			byte[] contents = NumericUtilities.convertStringToBytes(r.getString("contents"));

			long start = begin + offset;
			int length = (int) (end - start);
			if (length != contents.length) {
				Msg.warn(this, "Received fewer bytes than indicated by bounds");
			}
			int diff = (int) (start - addr);
			int newPos = pos + diff;
			max = Math.max(max, newPos + length);
			buf.position(newPos);
			buf.put(contents);
			rangeSet.add(Range.closedOpen(start, end));
		}
		buf.position(max);
		return rangeSet;
	}
}
