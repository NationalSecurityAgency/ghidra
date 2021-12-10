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
package agent.lldb.lldb.util;

import java.lang.reflect.Method;

import agent.lldb.lldb.DebugBreakpoint;
import agent.lldb.lldb.DebugClient.ChangeProcessState;
import agent.lldb.lldb.DebugClient.ChangeSessionState;
import agent.lldb.lldb.DebugClient.ChangeThreadState;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.lldb.DebugClient.SessionStatus;
import agent.lldb.lldb.DebugEventCallbacks;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.lldb.DebugProcessInfo;
import agent.lldb.lldb.DebugSessionInfo;
import agent.lldb.lldb.DebugThreadInfo;
import ghidra.comm.util.BitmaskSet;

/**
 * A convenient abstract implementation of {@link DebugEventCallbacks}
 * 
 * This implementation automatically computes the value for {@link #getInterestMask()} based on the
 * overridden methods. The default implementations all return {@link DebugStatus#NO_CHANGE}, should
 * they happen to be called.
 */
public class DebugEventCallbacksAdapter implements DebugEventCallbacks {

	private BitmaskSet<DebugEvent> interests = new BitmaskSet<>(DebugEvent.class);

	public DebugEventCallbacksAdapter() {
		try {
			// Compute the interest mask based on methods that are overridden
			for (Method im : DebugEventCallbacks.class.getDeclaredMethods()) {
				Method m = this.getClass().getMethod(im.getName(), im.getParameterTypes());
				if (m.getDeclaringClass() == DebugEventCallbacksAdapter.class) {
					continue;
				}
				// The interface method is overridden, grab the annotation from the interface
				ForInterest fi = im.getAnnotation(ForInterest.class);
				if (fi == null) {
					throw new AssertionError("No ForInterest annotation present on " + m);
				}
				interests.add(fi.value());
			}
		}
		catch (NoSuchMethodException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public BitmaskSet<DebugEvent> getInterestMask() {
		return interests;
	}

	@Override
	public DebugStatus breakpoint(DebugBreakpoint bp) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus exitThread(int exitCode) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus exitProcess(int exitCode) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus createSession(DebugSessionInfo debugSessionInfo) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus exitSession(int exitCode) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus loadModule(DebugModuleInfo debugModuleInfo) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus unloadModule(String imageBaseName, long baseOffset) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus systemError(int error, int level) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus sessionStatus(SessionStatus status) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus changeSessionState(BitmaskSet<ChangeSessionState> flags) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus changeProcessState(BitmaskSet<ChangeProcessState> flags) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus changeThreadState(BitmaskSet<ChangeThreadState> flags) {
		return DebugStatus.NO_CHANGE;
	}
}
