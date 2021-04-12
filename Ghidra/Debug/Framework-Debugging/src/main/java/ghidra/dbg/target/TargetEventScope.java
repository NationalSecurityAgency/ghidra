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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * An object that can emit events affecting itself and its successors
 * 
 * <p>
 * Most often, this interface is supported by the (root) session.
 */
@DebuggerTargetObjectIface("EventScope")
public interface TargetEventScope extends TargetObject {

	String EVENT_OBJECT_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "event_thread";

	public enum TargetEventType {
		/**
		 * The session has stopped for an unspecified reason
		 */
		STOPPED(true),
		/**
		 * The session is running for an unspecified reason
		 * 
		 * <p>
		 * Note that execution state changes are communicated via {@link TargetExecutionStateful},
		 * since the sessiopn may specify such state on a per-target and/or per-thread basis.
		 */
		RUNNING(false),
		/**
		 * A new target process was created by this session
		 * 
		 * <p>
		 * If the new process is part of the session, too, it must be passed as a parameter.
		 */
		PROCESS_CREATED(false),
		/**
		 * A target process in this session has exited
		 */
		PROCESS_EXITED(false),
		/**
		 * A new target thread was created by this session
		 * 
		 * <p>
		 * The new thread must be part of the session, too, and must be given as the event thread.
		 */
		THREAD_CREATED(false),
		/**
		 * A target thread in this session has exited
		 */
		THREAD_EXITED(false),
		/**
		 * A new module has been loaded by this session
		 * 
		 * <p>
		 * The new module must be passed as a parameter.
		 */
		MODULE_LOADED(false),
		/**
		 * A module has been unloaded by this session
		 */
		MODULE_UNLOADED(false),
		/**
		 * The session has stopped, because one if its targets was trapped by a breakpoint
		 * 
		 * <p>
		 * If the breakpoint (specification) is part of the session, too, it must be passed as a
		 * parameter. The trapped target must also be passed as a parameter.
		 */
		BREAKPOINT_HIT(true),
		/**
		 * The session has stopped, because a stepping command has completed
		 * 
		 * <p>
		 * The target completing the command must also be passed as a parameter, unless it is the
		 * event thread. If it is a thread, it must be given as the event thread.
		 */
		STEP_COMPLETED(true),
		/**
		 * The session has stopped, because one if its targets was trapped on an exception
		 * 
		 * <p>
		 * The trapped target must also be passed as a parameter, unless it is the event thread. If
		 * it is a thread, it must be given as the event thread.
		 */
		EXCEPTION(false),
		/**
		 * The session has stopped, because one of its targets was trapped on a signal
		 * 
		 * <p>
		 * The trapped target must also be passed as a parameter, unless it is the event thread. If
		 * it is a thread, it must be given as the event thread.
		 */
		SIGNAL(false);

		public final boolean impliesStop;

		private TargetEventType(boolean impliesStop) {
			this.impliesStop = impliesStop;
		}
	}

	/**
	 * If applicable, get the thread producing the last reported event
	 * 
	 * @return the thread or reference
	 */
	@TargetAttributeType(name = EVENT_OBJECT_ATTRIBUTE_NAME, hidden = true)
	public default TargetThread getEventThread() {
		return getTypedAttributeNowByName(EVENT_OBJECT_ATTRIBUTE_NAME, TargetThread.class, null);
	}
}
