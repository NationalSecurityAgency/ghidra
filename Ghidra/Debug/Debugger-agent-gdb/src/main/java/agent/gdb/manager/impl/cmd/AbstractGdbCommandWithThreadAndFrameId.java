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
 * An extension to {@link AbstractGdbCommandWithThreadId} that also passes the "{@code --frame}"
 * argument
 * 
 * @param <T> the type of object "returned" by the command
 */
public abstract class AbstractGdbCommandWithThreadAndFrameId<T>
		extends AbstractGdbCommandWithThreadId<T> {
	protected final Integer frameId;

	/**
	 * Construct a frame-specific command to be executed by the given manager
	 * 
	 * @param manager the manager to execute the command
	 * @param threadId the ID of the thread to pass to "{@code --thread}"
	 * @param frameId the ID "level" of the frame to pass to "{@code --frame}"
	 */
	protected AbstractGdbCommandWithThreadAndFrameId(GdbManagerImpl manager, Integer threadId,
			Integer frameId) {
		super(manager, threadId);
		this.frameId = frameId;
	}

	protected String makeFramePart() {
		return frameId == null ? "" : " --frame " + frameId;
	}

	/**
	 * Get the level of the frame to pass to "{@code --frame}"
	 * 
	 * @return the frame level
	 */
	public Integer getFrameId() {
		return frameId;
	}

	@Override
	public Integer impliesCurrentFrameId() {
		return frameId;
	}

	@Override
	protected String encode(String threadPart) {
		return encode(threadPart, makeFramePart());
	}

	/**
	 * Encode the command in GDB/MI, given the pre-constructed thread and frame parts
	 * 
	 * The given parts are preceded by spaces, but not followed by spaces. For example, a command
	 * can be properly constructed as:
	 * 
	 * <pre>
	 * return "-some-command" + threadPart + threadPart + " some-argument";
	 * </pre>
	 * 
	 * @param threadPart the "{@code --thread [ID]}" part
	 * @param framePart the "{@code --frame [level]}" part
	 * @return the encoded command
	 */
	protected abstract String encode(String threadPart, String framePart);
}
