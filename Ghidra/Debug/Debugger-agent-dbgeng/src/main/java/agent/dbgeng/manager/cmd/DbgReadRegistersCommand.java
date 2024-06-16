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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.DbgStackFrameOperations;
import agent.dbgeng.manager.impl.*;

/**
 * Implementation of {@link DbgStackFrameOperations#readRegisters(Set)}
 */
public class DbgReadRegistersCommand extends AbstractDbgCommand<Map<DbgRegister, BigInteger>> {

	private final DbgThreadImpl thread;
	private final Set<DbgRegister> regs;
	private DebugRegisters registers;
	private Map<DbgRegister, BigInteger> result = new LinkedHashMap<>();

	public DbgReadRegistersCommand(DbgManagerImpl manager, DbgThreadImpl thread, Integer frameId,
			Set<DbgRegister> regs) {
		super(manager);
		this.thread = thread;
		this.regs = regs;
	}

	@Override
	public Map<DbgRegister, BigInteger> complete(DbgPendingCommand<?> pending) {
		if (regs.isEmpty()) {
			return Collections.emptyMap();
		}
		return result;
	}

	@Override
	public void invoke() {
		try {
			setThread(thread);
			registers = manager.getClient().getRegisters();
			if (registers != null) {
				for (DbgRegister r : regs) {
					if (r.isBaseRegister()) {
						DebugValue value = registers.getValueByName(r.getName());
						if (value != null) {
							BigInteger bval = new BigInteger(value.encodeAsBytes());
							result.put(r, bval);
						}
					}
				}
			}
		} 
		finally {
			resetThread();
		}
	}
}
