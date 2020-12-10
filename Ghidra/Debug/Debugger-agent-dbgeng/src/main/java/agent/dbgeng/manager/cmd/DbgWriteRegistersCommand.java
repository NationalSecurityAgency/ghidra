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

import java.math.BigInteger;
import java.util.*;

import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugRegisters.DebugRegisterDescription;
import agent.dbgeng.dbgeng.DebugRegisters.DebugRegisterSource;
import agent.dbgeng.manager.DbgStackFrameOperations;
import agent.dbgeng.manager.impl.*;

/**
 * Implementation of {@link DbgStackFrameOperations#readRegisters(Set)}
 */
public class DbgWriteRegistersCommand extends AbstractDbgCommand<Void> {

	private final DbgThreadImpl thread;
	private final Map<DbgRegister, BigInteger> regVals;

	public DbgWriteRegistersCommand(DbgManagerImpl manager, DbgThreadImpl thread, Integer frameId,
			Map<DbgRegister, BigInteger> regVals) {
		super(manager);
		this.thread = thread;
		this.regVals = regVals;
	}

	@Override
	public void invoke() {
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId previous = so.getCurrentThreadId();
		so.setCurrentThreadId(thread.getId());
		DebugRegisters registers = manager.getRegisters();
		Map<Integer, DebugValue> values = new LinkedHashMap<>();
		for (DbgRegister r : regVals.keySet()) {
			try {
				BigInteger val = regVals.get(r);
				DebugRegisterDescription desc = registers.getDescription(r.getNumber());
				byte[] bytes = new byte[desc.type.byteLength];
				byte[] newBytes = val.toByteArray();
				for (int i = newBytes.length - 1, j = bytes.length - 1; i >= 0 &&
					j >= 0; i--, j--) {
					bytes[j] = newBytes[i];
				}
				DebugValue dv = desc.type.decodeBytes(bytes);
				values.put(r.getNumber(), dv);
			}
			catch (COMException e) {
				manager.getControl().errln("No register: " + r.getName());
			}
		}
		registers.setValues(DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE, values);
		so.setCurrentThreadId(previous);
	}
}
