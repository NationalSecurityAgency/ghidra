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
package agent.dbgeng.dbgeng;

import java.util.ArrayList;
import java.util.List;

import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.util.Msg;

/**
 * A wrapper for {@code IDebugControl} and its newer variants.
 */
public interface DebugControl extends DebugControlReentrant {
	public static final BitmaskSet<DebugOutputControl> SET_ALL_CLIENTS =
		BitmaskSet.of(DebugOutputControl.ALL_CLIENTS);
	public static final BitmaskSet<DebugExecute> SET_DEFAULT = BitmaskSet.of(DebugExecute.DEFAULT);

	public static enum DebugOutputLevel implements BitmaskUniverse {
		NORMAL(1 << 0), //
		ERROR(1 << 1), //
		WARNING(1 << 2), //
		VERBOSE(1 << 3), //
		PROMPT(1 << 4), //
		PROMPT_REGISTERS(1 << 5), //
		EXTENSION_WARNING(1 << 6), //
		OUTPUT_DEBUGEE(1 << 7), //
		OUTPUT_DEBUGEE_PROMPT(1 << 8), //
		OUTPUT_SYMBOLS(1 << 9), //
		OUTPUT_STATUS(1 << 10), //
		;

		private final int mask;

		DebugOutputLevel(int mask) {
			this.mask = mask;
		}

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum DebugOutputControl implements BitmaskUniverse {
		THIS_CLIENT(0), //
		ALL_CLIENTS(1), //
		ALL_OTHER_CLIENTS(2), //
		IGNORE(3), //
		LOG_ONLY(4), //
		SEND_MASK(7), //
		NOT_LOGGED(1 << 3), //
		OVERRIDE_MASK(1 << 4), //
		DML(1 << 5), //
		AMBIENT_DML(0xfffffffe), //
		AMBIENT_TEXT(0xffffffff), //
		AMBIENT(0xffffffff), //
		;

		private final int mask;

		DebugOutputControl(int mask) {
			this.mask = mask;
		}

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum DebugExecute implements BitmaskUniverse {
		DEFAULT(0), //
		ECHO(1 << 0), //
		NOT_LOGGED(1 << 1), //
		NO_REPEAT(1 << 2), //
		;

		private final int mask;

		DebugExecute(int mask) {
			this.mask = mask;
		}

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum DebugInterrupt {
		ACTIVE, //
		PASSIVE, //
		EXIT, //
		;
	}

	boolean getInterrupt();

	int getInterruptTimeout();

	void setInterruptTimeout(int seconds);

	void print(BitmaskSet<DebugOutputLevel> levels, String message);

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} that includes a newline.
	 * 
	 * @param levels the log levels for the message
	 * @param message the message
	 */
	void println(BitmaskSet<DebugOutputLevel> levels, String message);

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} that applies to a single level.
	 * 
	 * @param level the log level for the message
	 * @param message the message
	 */
	default void print(DebugOutputLevel level, String message) {
		print(BitmaskSet.of(level), message);
	}

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} that includes a newline and applies to a
	 * single level.
	 * 
	 * @param level the log level for the message
	 * @param message the message
	 */
	default void println(DebugOutputLevel level, String message) {
		println(BitmaskSet.of(level), message);
	}

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} at normal level.
	 * 
	 * @param message the message
	 */
	default void out(String message) {
		print(DebugOutputLevel.NORMAL, message);
	}

	/**
	 * A shortcut for {@link #println(BitmaskSet, String)} at normal level.
	 * 
	 * @param message the message
	 */
	default void outln(String message) {
		println(DebugOutputLevel.NORMAL, message);
	}

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} at warning level.
	 * 
	 * @param message the message
	 */
	default void warn(String message) {
		print(DebugOutputLevel.WARNING, message);
	}

	/**
	 * A shortcut for {@link #println(BitmaskSet, String)} at warning level.
	 * 
	 * @param message the message
	 */
	default void warnln(String message) {
		println(DebugOutputLevel.WARNING, message);
	}

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} at error level.
	 * 
	 * @param message the message
	 */
	default void err(String message) {
		print(DebugOutputLevel.ERROR, message);
	}

	/**
	 * A shortcut for {@link #println(BitmaskSet, String)} at error level.
	 * 
	 * @param message the message
	 */
	default void errln(String message) {
		println(DebugOutputLevel.ERROR, message);
	}

	/**
	 * A shortcut for {@link #print(BitmaskSet, String)} at verbose level.
	 * 
	 * @param message the message
	 */
	default void verb(String message) {
		print(DebugOutputLevel.VERBOSE, message);
	}

	/**
	 * A shortcut for {@link #println(BitmaskSet, String)} at verbose level.
	 * 
	 * @param message the message
	 */
	default void verbln(String message) {
		println(DebugOutputLevel.VERBOSE, message);
	}

	<T extends DebugValue> T evaluate(Class<T> desiredType, String expression);

	void execute(BitmaskSet<DebugOutputControl> ctl, String str, BitmaskSet<DebugExecute> flags);

	/**
	 * A shortcut for {@link #execute(BitmaskSet, String, BitmaskSet)} outputting to all clients
	 * with the default execution flag.
	 * 
	 * @param str the command string
	 */
	default void execute(String str) {
		execute(SET_ALL_CLIENTS, str, SET_DEFAULT);
	}

	void prompt(BitmaskSet<DebugOutputControl> ctl, String message);

	String getPromptText();

	void returnInput(String input);

	DebugStatus getExecutionStatus();

	void setExecutionStatus(DebugStatus status);

	int getNumberBreakpoints();

	DebugBreakpoint getBreakpointByIndex(int index);

	/**
	 * Shortcut to retrieve all breakpoints for the current process.
	 * 
	 * <p>
	 * Uses {@link #getNumberBreakpoints()} and {@link #getBreakpointByIndex(int)} to enumerate all
	 * breakpoints for the current process.
	 * 
	 * @return the list of retrieved breakpoints.
	 */
	default List<DebugBreakpoint> getBreakpoints() {
		int count = getNumberBreakpoints();
		List<DebugBreakpoint> result = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			try {
				result.add(getBreakpointByIndex(i));
			}
			catch (COMException e) {
				if (!COMUtilsExtra.isE_NOINTERFACE(e)) {
					throw e;
				}
				Msg.trace(this, "Discarding private breakpoint at index " + i);
			}
		}
		return result;
	}

	/**
	 * Get a breakpoint by ID
	 * 
	 * According to the MSDN, though the IDs may be global, this method should only succeed for
	 * breakpoints belonging to the current process.
	 * 
	 * @param id
	 * @return
	 */
	DebugBreakpoint getBreakpointById(int id);

	/**
	 * Add a (resolved) breakpoint with the given type and desired id
	 * 
	 * <p>
	 * This is equivalent, in part, to the {@code bp} command.
	 * 
	 * @param type the type
	 * @param desiredId the desired id
	 * @return the breakpoint, disabled at offset 0
	 */
	DebugBreakpoint addBreakpoint(BreakType type, int desiredId);

	/**
	 * Add a (resolved) breakpoint with the given type and any id
	 * 
	 * <p>
	 * This is equivalent, in part, to the {@code bp} command.
	 * 
	 * @param type the type
	 * @return the breakpoint, disable at offset 0
	 */
	DebugBreakpoint addBreakpoint(BreakType type);

	/**
	 * Add an unresolved breakpoint with the given type and desired id
	 * 
	 * <p>
	 * This is equivalent, in part, to the {@code bu} command. See the MSDN for a comparison of
	 * {@code bu} and {@code bp}.
	 * 
	 * @param type the type
	 * @param desiredId the desired id
	 * @return the breakpoint, disabled at offset 0
	 */
	DebugBreakpoint addBreakpoint2(BreakType type, int desiredId);

	/**
	 * Add an unresolved breakpoint with the given type and any id
	 * 
	 * <p>
	 * This is equivalent, in part, to the {@code bu} command. See the MSDN for a comparison of
	 * {@code bu} and {@code bp}.
	 * 
	 * @param desiredId the desired id
	 * @return the breakpoint, disabled at offset 0
	 */
	DebugBreakpoint addBreakpoint2(BreakType type);

	void waitForEvent(int timeout);

	DebugEventInformation getLastEventInformation();

	DebugStackInformation getStackTrace(long frameOffset, long stackOffset, long instructionOffset);

	/**
	 * Shortcut for {@link #waitForEvent(int)} with infinite timeout.
	 */
	default void waitForEvent() {
		waitForEvent(WinBase.INFINITE);
	}

	int getActualProcessorType();

	int getEffectiveProcessorType();

	int getExecutingProcessorType();

	int getDebuggeeType();
}
