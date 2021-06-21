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
package agent.dbgeng.dbgeng;

/**
 * Information about a thread.
 * 
 * <p>
 * The fields correspond to parameters taken by {@code CreateThread} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class DebugThreadInfo {
	public final long handle;
	public final long dataOffset;
	public final long startOffset;

	public DebugThreadInfo(long handle, long dataOffset, long startOffset) {
		this.handle = handle;
		this.dataOffset = dataOffset;
		this.startOffset = startOffset;
	}

	@Override
	public String toString() {
		return String.format("<%s@%08x handle=0x%04x,dataOffset=0x%08x,startOffset=0x%08x>",
			getClass().getSimpleName(), System.identityHashCode(this),
			handle, dataOffset, startOffset);
	}
}
