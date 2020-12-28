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

import java.util.List;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * An object that can emit events affecting itself and its successors
 * 
 * <p>
 * Most often, this interface is supported by the (root) session.
 */
@DebuggerTargetObjectIface("EventScope")
public interface TargetEventScope<T extends TargetEventScope<T>> extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetEventScope<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetEventScope.class;

	String EVENT_PROCESS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "event_process";
	String EVENT_THREAD_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "event_thread";

	public enum TargetEventType {
		/**
		 * The session has stopped for an unspecified reason
		 */
		STOPPED,
		/**
		 * The session is running for an unspecified reason
		 * 
		 * <p>
		 * Note that execution state changes are communicated via {@link TargetExecutionStateful},
		 * since the sessiopn may specify such state on a per-target and/or per-thread basis.
		 */
		RUNNING,
		/**
		 * A new target process was created by this session
		 * 
		 * <p>
		 * If the new process is part of the session, too, it must be passed as a parameter.
		 */
		PROCESS_CREATED,
		/**
		 * A target process in this session has exited
		 */
		PROCESS_EXITED,
		/**
		 * A new target thread was created by this session
		 * 
		 * <p>
		 * The new thread must be part of the session, too, and must be given as the event thread.
		 */
		THREAD_CREATED,
		/**
		 * A target thread in this session has exited
		 */
		THREAD_EXITED,
		/**
		 * A new module has been loaded by this session
		 * 
		 * <p>
		 * The new module must be passed as a parameter.
		 */
		MODULE_LOADED,
		/**
		 * A module has been unloaded by this session
		 */
		MODULE_UNLOADED,
		/**
		 * The session has stopped, because one if its targets was trapped by a breakpoint
		 * 
		 * <p>
		 * If the breakpoint (specification) is part of the session, too, it must be passed as a
		 * parameter. The trapped target must also be passed as a parameter.
		 */
		BREAKPOINT_HIT,
		/**
		 * The session has stopped, because a stepping command has completed
		 * 
		 * <p>
		 * The target completing the command must also be passed as a parameter, unless it is the
		 * event thread. If it is a thread, it must be given as the event thread.
		 */
		STEP_COMPLETED,
		/**
		 * The session has stopped, because one if its targets was trapped on an exception
		 * 
		 * <p>
		 * The trapped target must also be passed as a parameter, unless it is the event thread. If
		 * it is a thread, it must be given as the event thread.
		 */
		EXCEPTION,
		/**
		 * The session has stopped, because one of its targets was trapped on a signal
		 * 
		 * <p>
		 * The trapped target must also be passed as a parameter, unless it is the event thread. If
		 * it is a thread, it must be given as the event thread.
		 */
		SIGNAL,
	}

	/**
	 * If applicable, get the process producing the last reported event
	 * 
	 * <p>
	 * TODO: This is currently the hexadecimal PID. It should really be a ref to the process object.
	 * 
	 * <p>
	 * TODO: Since the event thread will be a successor of the event process, this may not be
	 * needed, but perhaps keep it for convenience.
	 * 
	 * @return the process or reference
	 */
	@TargetAttributeType(name = EVENT_PROCESS_ATTRIBUTE_NAME, hidden = true)
	public default /*TODO: TypedTargetObjectRef<? extends TargetProcess<?>>*/ String getEventProcess() {
		return getTypedAttributeNowByName(EVENT_PROCESS_ATTRIBUTE_NAME, String.class, null);
	}

	/**
	 * If applicable, get the thread producing the last reported event
	 * 
	 * <p>
	 * TODO: This is currently the hexadecimal TID. It should really be a ref to the thread object.
	 * 
	 * @return the thread or reference
	 */
	@TargetAttributeType(name = EVENT_THREAD_ATTRIBUTE_NAME, hidden = true)
	public default /*TODO: TypedTargetObjectRef<? extends TargetThread<?>>*/ String getEventThread() {
		return getTypedAttributeNowByName(EVENT_THREAD_ATTRIBUTE_NAME, String.class, null);
	}

	public interface TargetEventScopeListener extends TargetObjectListener {
		/**
		 * An event affecting a target in this scope has occurred
		 * 
		 * <p>
		 * When present, this callback must be invoked before any other callback which results from
		 * this event, except creation events. E.g., for PROCESS_EXITED, this must be called before
		 * the affected process is removed from the tree.
		 * 
		 * <p>
		 * Whenever possible, event thread must be given. This is often the thread given focus by
		 * the debugger immediately upon stopping for the event. Parameters are not (yet) strictly
		 * specified, but it should include the stopped target, if that target is not already given
		 * by the event thread. It may optionally contain other useful information, such as an exit
		 * code, but no listener should depend on that information being given.
		 * 
		 * <p>
		 * The best way to communicate to users what has happened is via the description. Almost
		 * every other result of an event is communicated by other means in the model, e.g., state
		 * changes, object creation, destruction. The description should contain as much information
		 * as possible to cue users as to why the other changes have occurred, and point them to
		 * relevant objects. For example, if trapped on a breakpoint, the description might contain
		 * the breakpoint's identifier. If the debugger prints a message for this event, that
		 * message is probably a sufficient description.
		 * 
		 * @param object the event scope
		 * @param eventThread if applicable, the thread causing the event
		 * @param type the type of event
		 * @param description a human-readable description of the event
		 * @param parameters extra parameters for the event. TODO: Specify these for each type
		 */
		default void event(TargetEventScope<?> object,
				TypedTargetObjectRef<? extends TargetThread<?>> eventThread, TargetEventType type,
				String description, List<Object> parameters) {
		}
	}
}
