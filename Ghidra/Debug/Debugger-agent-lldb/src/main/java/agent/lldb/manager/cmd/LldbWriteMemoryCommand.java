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

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbProcess#writeMemory(long, ByteBuffer, int)}
 */
public class LldbWriteMemoryCommand extends AbstractLldbCommand<Void> {

	private final SBProcess process;
	private final Address addr;
	private final ByteBuffer buf;
	private final int len;

	public LldbWriteMemoryCommand(LldbManagerImpl manager, SBProcess process, Address addr,
			ByteBuffer buf, int len) {
		super(manager);
		this.process = process;
		this.addr = addr;
		this.buf = buf.duplicate();
		this.len = len;
	}

	@Override
	public void invoke() {
		BigInteger offset = addr.getOffsetAsBigInteger();
		byte[] byteArray = buf.array();
		ByteArray buffer = new ByteArray(len);
		for (int i = 0; i < len; i++) {
			buffer.setitem(i, byteArray[i]);
		}
		SBError error = new SBError();
		process.WriteMemory(offset, buffer, len, error);
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, error.GetType() + ":" + stream.GetData());
		}
		buffer.delete();
	}

}
