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
package agent.dbgeng.manager.impl;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgStackFrame;
import agent.dbgeng.manager.cmd.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;

public class DbgStackFrameImpl implements DbgStackFrame {

	protected final DbgManagerImpl manager;
	protected final DbgThreadImpl thread;
	protected final int level;
	protected final BigInteger addr;
	protected final String func;
	private long funcTableEntry;
	private long frameOffset;
	private long returnOffset;
	private long stackOffset;
	private boolean virtual;

	private long params[] = new long[4];

	public DbgStackFrameImpl(DbgThreadImpl thread, int level, BigInteger addr, String func) {
		this.manager = thread.manager;
		this.thread = thread;
		this.level = level;
		this.addr = addr;
		this.func = func;
	}

	public DbgStackFrameImpl(DbgThreadImpl thread, int level, BigInteger addr, long funcTableEntry,
			long frameOffset, long returnOffset, long stackOffset, boolean virtual, long param0,
			long param1, long param2, long param3) {
		this.manager = thread.manager;
		this.thread = thread;
		this.level = level;
		this.addr = addr;
		this.func = null;
		this.funcTableEntry = funcTableEntry;
		this.frameOffset = frameOffset;
		this.returnOffset = returnOffset;
		this.stackOffset = stackOffset;
		this.virtual = virtual;
		this.params[0] = param0;
		this.params[1] = param1;
		this.params[2] = param2;
		this.params[3] = param3;
	}

	@Override
	public String toString() {
		return "<DbgStackFrame: level=" + level + ",addr=0x" + addr.toString(16) + ",func='" +
			func + "'>";
	}

	@Override
	public int getLevel() {
		return level;
	}

	@Override
	public BigInteger getAddress() {
		return addr;
	}

	@Override
	public String getFunction() {
		return func;
	}

	@Override
	public DbgThreadImpl getThread() {
		return thread;
	}

	@Override
	public long getFuncTableEntry() {
		return funcTableEntry;
	}

	@Override
	public long getFrameOffset() {
		return frameOffset;
	}

	@Override
	public long getReturnOffset() {
		return returnOffset;
	}

	@Override
	public long getStackOffset() {
		return stackOffset;
	}

	@Override
	public boolean getVirtual() {
		return virtual;
	}

	@Override
	public long[] getParams() {
		return params;
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return thread.setActive();
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return manager.execute(new DbgEvaluateCommand(manager, expression));
	}

	@Override
	public CompletableFuture<Map<DbgRegister, BigInteger>> readRegisters(Set<DbgRegister> regs) {
		return AsyncUtils.sequence(TypeSpec.map(DbgRegister.class, BigInteger.class)).then(seq -> {
			manager.execute(new DbgReadRegistersCommand(manager, thread, level, regs))
					.handle(seq::exit);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> writeRegisters(Map<DbgRegister, BigInteger> regVals) {
		return manager.execute(new DbgWriteRegistersCommand(manager, thread, level, regVals));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		return manager
				.execute(new DbgConsoleExecCommand(manager, command,
					DbgConsoleExecCommand.Output.CONSOLE))
				.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return manager.execute(
			new DbgConsoleExecCommand(manager, command, DbgConsoleExecCommand.Output.CAPTURE));
	}
}
