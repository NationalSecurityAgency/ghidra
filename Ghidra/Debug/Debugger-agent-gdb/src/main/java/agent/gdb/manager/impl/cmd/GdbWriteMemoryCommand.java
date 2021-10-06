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

import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.GdbPendingCommand;

/**
 * Implementation of {@link GdbThread#writeMemory(long, ByteBuffer, int)}
 */
public class GdbWriteMemoryCommand extends AbstractGdbCommandWithThreadId<Void> {

	private final long addr;
	private final ByteBuffer buf;
	private final int len;

	public GdbWriteMemoryCommand(GdbManagerImpl manager, Integer threadId, long addr,
			ByteBuffer buf, int len) {
		super(manager, threadId);
		this.addr = addr;
		this.buf = buf.duplicate();
		this.len = len;
	}

	@Override
	protected String encode(String threadPart) {
		ByteBuffer dup = buf.duplicate();
		StringBuilder b = new StringBuilder();
		b.append("-data-write-memory-bytes");
		b.append(threadPart);
		b.append(" 0x");
		b.append(Long.toHexString(addr));
		b.append(" ");
		for (int i = 0; i < len; i++) {
			int n = dup.get();
			if (n < 0) {
				n += 256;
			}
			b.append(String.format("%02x", n));
		}
		return b.toString();
	}

	@Override
	public Void complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);
		return null;
	}
}
