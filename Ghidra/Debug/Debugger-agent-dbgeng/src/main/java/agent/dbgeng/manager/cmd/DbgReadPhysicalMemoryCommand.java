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
package agent.dbgeng.manager.cmd;

import java.nio.ByteBuffer;

import com.google.common.collect.*;

import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;

/**
 * Implementation of {@link DbgThread#readMemory(long, ByteBuffer, int)}
 */
public class DbgReadPhysicalMemoryCommand extends AbstractDbgCommand<RangeSet<Long>> {

	private final long addr;
	private final ByteBuffer buf;
	private final int len;

	private int readLen;

	public DbgReadPhysicalMemoryCommand(DbgManagerImpl manager, long addr, ByteBuffer buf,
			int len) {
		super(manager);
		this.addr = addr;
		this.buf = buf;
		this.len = len;
	}

	@Override
	public RangeSet<Long> complete(DbgPendingCommand<?> pending) {
		RangeSet<Long> rangeSet = TreeRangeSet.create();
		rangeSet.add(Range.closedOpen(addr, addr + readLen));
		return rangeSet;
	}

	@Override
	public void invoke() {
		readLen = manager.getDataSpaces().readPhysical(addr, buf, len);
	}
}
