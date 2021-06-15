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
package ghidra.app.plugin.core.debug.gui.thread;

public enum ThreadState {
	/**
	 * The last recorded state is alive, but the recorder is not tracking the live thread
	 * 
	 * This state is generally erroneous. If it is seen, the recorder has fallen out of sync with
	 * the live session and/or the trace.
	 */
	UNKNOWN,
	/**
	 * The last recorded state is alive, but there is no live session to know STOPPED or RUNNING
	 */
	// TODO: Should the thread state transitions be recorded?
	ALIVE,
	/**
	 * The thread is alive, but suspended
	 */
	STOPPED,
	/**
	 * The thread is alive and running
	 */
	RUNNING,
	/**
	 * The thread has been terminated (either as recorded, or as reported by the live session)
	 */
	TERMINATED;
}
