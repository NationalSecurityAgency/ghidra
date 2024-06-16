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

import agent.dbgeng.manager.impl.DbgManagerImpl;
import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;

public abstract class AbstractDbgReadCommand extends AbstractDbgCommand<ULongSpanSet> {

	private final long addr;
	private final ByteBuffer buf;
	private final int len;

	private int readLen;

	protected AbstractDbgReadCommand(DbgManagerImpl manager, long addr, ByteBuffer buf, int len) {
		super(manager);
		this.addr = addr;
		this.buf = buf;
		this.len = len;
	}

	protected abstract int doRead(long addr, ByteBuffer buf, int len);

	@Override
	public void invoke() {
		readLen = doRead(addr, buf, len);
	}

	@Override
	public ULongSpanSet complete(DbgPendingCommand<?> pending) {
		if (readLen == 0) {
			return ULongSpanSet.of();
		}
		return ULongSpanSet.of(ULongSpan.extent(addr, readLen));
	}
}
