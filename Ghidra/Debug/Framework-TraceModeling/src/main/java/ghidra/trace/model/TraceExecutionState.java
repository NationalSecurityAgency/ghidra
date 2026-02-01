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
package ghidra.trace.model;

/**
 * The execution state of a debug target object
 */
public enum TraceExecutionState {
	/**
	 * The object has been created, but it not yet alive
	 * 
	 * <p>
	 * This may apply, e.g., to a GDB "Inferior," which has no yet been used to launch or attach to
	 * a process.
	 */
	INACTIVE,

	/**
	 * The object is alive, but its execution state is unspecified
	 * 
	 * <p>
	 * Implementations should use {@link #STOPPED} and {@link #RUNNING} whenever possible. For some
	 * objects, e.g., a process, this is conventionally determined by its parts, e.g., threads: A
	 * process is running when <em>any</em> of its threads are running. It is stopped when
	 * <em>all</em> of its threads are stopped. For the clients' sakes, all models should implement
	 * these conventions internally.
	 */
	ALIVE,

	/**
	 * The object is alive, but not executing
	 */
	STOPPED,

	/**
	 * The object is alive and executing
	 * 
	 * <p>
	 * "Running" is loosely defined. For example, with respect to a thread, it may indicate the
	 * thread is currently executing, waiting on an event, or scheduled for execution. It does not
	 * necessarily mean it is executing on a CPU at this exact moment.
	 */
	RUNNING,

	/**
	 * The object is no longer alive
	 * 
	 * <p>
	 * The object still exists but no longer represents something alive. This could be used for
	 * stale handles to objects which may still be queried (e.g., for a process exit code), or e.g.,
	 * a GDB "Inferior," which could be re-used to launch or attach to another process.
	 */
	TERMINATED;
}
