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
package agent.gdb.manager.impl.cmd;

import agent.gdb.manager.impl.GdbManagerImpl;

/**
 * An extension to {@link AbstractGdbCommand} that passes the "{@code --thread}" argument
 *
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractGdbCommandWithThreadId<T> extends AbstractGdbCommand<T> {
	protected static final String MI2_THREAD_PREFIX = " --thread ";
	protected final Integer threadId;

	/**
	 * Construct a thread-specific command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 * @param threadId the ID of the thread to pass to "{@code --thread}"
	 */
	protected AbstractGdbCommandWithThreadId(GdbManagerImpl manager, Integer threadId) {
		super(manager);
		this.threadId = threadId;
	}

	protected String makeThreadPart() {
		return threadId == null ? "" : MI2_THREAD_PREFIX + threadId;
	}

	@Override
	public String encode() {
		return encode(makeThreadPart());
	}

	/**
	 * Get the ID of the thread to pass to "{@code --thread}"
	 * 
	 * @return the thread ID
	 */
	public Integer getThreadId() {
		return threadId;
	}

	@Override
	public Integer impliesCurrentThreadId() {
		return threadId;
	}

	/**
	 * Encode the command in GDB/MI, given the pre-constructed thread argument part
	 * 
	 * <p>
	 * The given thread argument is preceded by a space, but not followed by one. For example, a
	 * command can be properly constructed as:
	 * 
	 * <pre>
	 * return "-some-command" + threadPart + " some-argument";
	 * </pre>
	 * 
	 * @param threadPart the "{@code --thread [ID]}" part
	 * @return the encoded command
	 */
	protected abstract String encode(String threadPart);
}
