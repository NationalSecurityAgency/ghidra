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
 * An object which has an execution life cycle
 * 
 * @deprecated Will be removed in 11.3. Portions may be refactored into trace object database.
 */
@Deprecated(forRemoval = true, since = "11.2")
@DebuggerTargetObjectIface("ExecutionStateful")
public interface TargetExecutionStateful extends TargetObject {

	String STATE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "state";

	/**
	 * The execution state of a debug target object
	 */
	public enum TargetExecutionState {
		/**
		 * The object has been created, but it not yet alive
		 * 
		 * <p>
		 * This may apply, e.g., to a GDB "Inferior," which has no yet been used to launch or attach
		 * to a process.
		 */
		INACTIVE(false, false, false, false),

		/**
		 * The object is alive, but its execution state is unspecified
		 * 
		 * <p>
		 * Implementations should use {@link #STOPPED} and {@link #RUNNING} whenever possible. For
		 * some objects, e.g., a process, this is conventionally determined by its parts, e.g.,
		 * threads: A process is running when <em>any</em> of its threads are running. It is stopped
		 * when <em>all</em> of its threads are stopped. For the clients' sakes, all models should
		 * implement these conventions internally.
		 */
		ALIVE(true, false, false, false),

		/**
		 * The object is alive, but not executing
		 */
		STOPPED(true, false, true, false),

		/**
		 * The object is alive and executing
		 * 
		 * <p>
		 * "Running" is loosely defined. For example, with respect to a thread, it may indicate the
		 * thread is currently executing, waiting on an event, or scheduled for execution. It does
		 * not necessarily mean it is executing on a CPU at this exact moment.
		 */
		RUNNING(true, true, false, false),

		/**
		 * The object is no longer alive
		 * 
		 * <p>
		 * The object still exists but no longer represents something alive. This could be used for
		 * stale handles to objects which may still be queried (e.g., for a process exit code), or
		 * e.g., a GDB "Inferior," which could be re-used to launch or attach to another process.
		 */
		TERMINATED(false, false, false, true);

		private final boolean alive;
		private final boolean running;
		private final boolean stopped;
		private final boolean terminated;

		private TargetExecutionState(boolean alive, boolean running, boolean stopped, boolean terminated) {
			this.alive = alive;
			this.running = running;
			this.stopped = stopped;
			this.terminated = terminated;
		}

		/**
		 * Check if this state implies the object is alive
		 * 
		 * @return true if alive
		 */
		public boolean isAlive() {
			return alive;
		}

		/**
		 * Check if this state implies the object is running
		 * 
		 * @return true if running
		 */
		public boolean isRunning() {
			return running;
		}

		/**
		 * Check if this state implies the object is stopped
		 * 
		 * @return true if stopped
		 */
		public boolean isStopped() {
			return stopped;
		}

		/**
		 * Check if this state implies the object was terminated
		 * 
		 * @return true if terminated
		 */
		public boolean isTerminated() {
			return terminated;
		}

		/**
		 * Check if this state is ambiguous
		 * 
		 * @return true if terminated
		 */
		public boolean isUnknown() {
			return !stopped && !running && !terminated;
		}
	}

	/**
	 * Get the current execution state of this object
	 * 
	 * @return the state
	 */
	@TargetAttributeType(name = STATE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default TargetExecutionState getExecutionState() {
		return getTypedAttributeNowByName(STATE_ATTRIBUTE_NAME, TargetExecutionState.class,
			TargetExecutionState.INACTIVE);
	}
}
