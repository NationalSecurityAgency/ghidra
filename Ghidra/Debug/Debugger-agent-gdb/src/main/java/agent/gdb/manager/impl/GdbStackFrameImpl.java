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
package agent.gdb.manager.impl;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbRegister;
import agent.gdb.manager.GdbStackFrame;
import agent.gdb.manager.impl.cmd.*;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import agent.gdb.manager.parsing.GdbParsingUtils;

public class GdbStackFrameImpl implements GdbStackFrame {
	protected final GdbManagerImpl manager;
	protected final GdbThreadImpl thread;
	protected final int level;
	protected final BigInteger addr;
	protected final String func;

	public static GdbStackFrameImpl fromFieldList(GdbThreadImpl thread, GdbMiFieldList fields) {
		String lvlString = fields.getString("level");
		// NOTE: When given with breakpoint-hit, level is absent. Safe to assume innermost.
		int level = lvlString == null ? 0 : Integer.parseInt(lvlString);
		BigInteger addr = GdbParsingUtils.parsePrefixedHexBig(fields.getString("addr"));
		String func = fields.getString("func");
		return new GdbStackFrameImpl(thread, level, addr, func);
	}

	public GdbStackFrameImpl(GdbThreadImpl thread, int level, BigInteger addr, String func) {
		this.manager = thread.manager;
		this.thread = thread;
		this.level = level;
		this.addr = addr;
		this.func = func;
	}

	@Override
	public String toString() {
		String strAddr = addr == null ? "<null>" : addr.toString(16);
		String strFunc = func == null ? "<null>" : func.toString();
		return "<GdbStackFrame: level=" + level + ",addr=0x" + strAddr + ",func='" + strFunc + "'>";
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
	public GdbThreadImpl getThread() {
		return thread;
	}

	@Override
	public GdbStackFrame fillWith(GdbStackFrame frame) {
		if (addr != null && func != null) {
			return this;
		}
		BigInteger fAddr = addr;
		if (fAddr == null) {
			if (frame != null && frame.getAddress() != null) {
				fAddr = frame.getAddress();
			}
			else {
				fAddr = BigInteger.ZERO;
			}
		}
		String fFunc = func;
		if (fFunc == null) {
			if (frame != null && frame.getFunction() != null) {
				fFunc = frame.getFunction();
			}
			else {
				fFunc = "";
			}
		}
		return new GdbStackFrameImpl(thread, level, fAddr, fFunc);
	}

	@Override
	public CompletableFuture<Void> setActive(boolean internal) {
		return manager
				.execute(new GdbSetActiveThreadCommand(manager, thread.getId(), level, internal));
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return manager.execute(new GdbEvaluateCommand(manager, thread.getId(), level, expression));
	}

	@Override
	public CompletableFuture<Map<GdbRegister, BigInteger>> readRegisters(Set<GdbRegister> regs) {
		return thread.getInferior().syncEndianness().thenCompose(__ -> {
			return manager.execute(new GdbReadRegistersCommand(manager, thread, level, regs));
		});
	}

	@Override
	public CompletableFuture<Void> writeRegisters(Map<GdbRegister, BigInteger> regVals) {
		return thread.getInferior().syncEndianness().thenCompose(__ -> {
			return manager.execute(new GdbWriteRegistersCommand(manager, thread, level, regVals));
		});
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		return manager.execute(new GdbConsoleExecCommand(manager, thread.getId(), level, command,
			GdbConsoleExecCommand.Output.CONSOLE)).thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return manager.execute(new GdbConsoleExecCommand(manager, thread.getId(), level, command,
			GdbConsoleExecCommand.Output.CAPTURE));
	}
}
