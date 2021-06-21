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
package ghidra.dbg.jdi.manager.impl;

import com.sun.jdi.ThreadReference;

public enum DebugStatus {
	NO_CHANGE(false, null, 13), //
	GO(true, ThreadReference.THREAD_STATUS_RUNNING, 10), //
	STEP_OVER(true, ThreadReference.THREAD_STATUS_RUNNING, 7), //
	STEP_INTO(true, ThreadReference.THREAD_STATUS_RUNNING, 5), //
	BREAK(false, ThreadReference.THREAD_STATUS_RUNNING, 0), //
	NO_DEBUGGEE(true, null, 1), // shouldWait is true to handle process creation
	STEP_BRANCH(true, null, 6), //
	IGNORE_EVENT(false, null, 11), //
	RESTART_REQUESTED(true, null, 12), //
	OUT_OF_SYNC(false, null, 2), //
	WAIT_INPUT(false, null, 3), //
	TIMEOUT(false, null, 4), //
	;

	public static final long MASK = 0xaf;
	public static final long INSIDE_WAIT = 0x100000000L;
	public static final long WAIT_TIMEOUT = 0x200000000L;

	DebugStatus(boolean shouldWait, Integer threadState, int precedence) {
		this.shouldWait = shouldWait;
		this.threadState = threadState;
		this.precedence = precedence;
	}

	public final boolean shouldWait;
	public final Integer threadState;
	public final int precedence; // 0 is highest

	public static DebugStatus fromArgument(long argument) {
		return values()[(int) (argument & MASK)];
	}

	public static boolean isInsideWait(long argument) {
		return (argument & INSIDE_WAIT) != 0;
	}

	public static boolean isWaitTimeout(long argument) {
		return (argument & WAIT_TIMEOUT) != 0;
	}

	public static DebugStatus update(DebugStatus added) {
		return added;
	}

}
