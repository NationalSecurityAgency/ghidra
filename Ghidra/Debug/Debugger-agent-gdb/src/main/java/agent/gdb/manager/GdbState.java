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
package agent.gdb.manager;

/**
 * Describes the running state of GDB
 * 
 * The manager is initialized in the {@link #NOT_STARTED} state. When {@link GdbManager#start()} is
 * called, it enters the {@link #STARTING} state immediately upon successfully launching the GDB
 * session. Once GDB issues its first prompt, it enters the {@link #STOPPED} state. The state then
 * switches between {@link #RUNNING} and {@link #STOPPED} according to the execution state of its
 * inferior(s). When the GDB session exits, it enters the {@link #EXIT} state.
 * 
 * This is also used to describe the state of threads and inferiors. Only {@link #STOPPED},
 * {@link #RUNNING}, and {@link #EXIT} apply to inferiors. Only {@link #STOPPED} and
 * {@link #RUNNING} apply to threads.
 */
public enum GdbState {
	/**
	 * GDB is not alive, because it has not be started
	 */
	NOT_STARTED {
		@Override
		public boolean isAlive() {
			return false;
		}
	},
	/**
	 * GDB is alive, but has not issued its first prompt, yet
	 */
	STARTING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * GDB, the inferior, or the thread, is stopped
	 */
	STOPPED {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * GDB, the inferior, or the thread, is running
	 */
	RUNNING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * GDB or the inferior has exited
	 */
	EXIT {
		@Override
		public boolean isAlive() {
			return false;
		}
	};

	public abstract boolean isAlive();
}
