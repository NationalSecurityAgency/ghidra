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
package agent.lldb.manager.cmd;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import com.google.common.collect.*;

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbProcess#readMemory(long, ByteBuffer, int)}
 */
public class LldbReadMemoryCommand extends AbstractLldbCommand<RangeSet<Long>> {

	private final SBProcess process;
	private final Address addr;
	private final ByteBuffer buf;
	private final int len;

	public LldbReadMemoryCommand(LldbManagerImpl manager, SBProcess process, Address addr,
			ByteBuffer buf, int len) {
		super(manager);
		this.process = process;
		this.addr = addr;
		this.buf = buf;
		this.len = len;
	}

	@Override
	public RangeSet<Long> complete(LldbPendingCommand<?> pending) {
		RangeSet<Long> rangeSet = TreeRangeSet.create();
		rangeSet.add(Range.closedOpen(addr.getOffset(), addr.getOffset() + len));
		return rangeSet;
	}

	@Override
	public void invoke() {
		BigInteger offset = addr.getOffsetAsBigInteger();
		SBError error = new SBError();
		ByteArray buffer = new ByteArray(len);
		long read = process.ReadMemory(offset, buffer, len, error);
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, error.GetType() + ":" + stream.GetData());
			return;
		}
		for (int i = 0; i < read; i++) {
			buf.put(i, buffer.getitem(i));
		}
		buffer.delete();
		/*
		for (int i = 0; i < len; i += 8) {
			BigInteger increment = new BigInteger(Integer.toString(i));
			BigInteger res = process.ReadPointerFromMemory(offset.add(increment), error);
			byte[] bytes = res.toByteArray();
			for (int j = 0; j < bytes.length; j++) {
				buf.put(i + j, bytes[bytes.length - j - 1]);
			}
			if (!error.Success()) {
				SBStream stream = new SBStream();
				error.GetDescription(stream);
				Msg.error(this, error.GetType() + ":" + stream.GetData());
				break;
			}
		}
		*/
	}
}
