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
 * Information about a process.
 * 
 * The fields correspond to parameters taken by {@code CreateProcess} of
 * {@code IDebugEventCallbacks}. Note that parameters common to other callbacks have been factored
 * into types aggregated here.
 */
public class DebugProcessInfo {
	public final long handle;
	public final DebugModuleInfo moduleInfo;
	public final DebugThreadInfo initialThreadInfo;

	public DebugProcessInfo(long handle, DebugModuleInfo moduleInfo,
			DebugThreadInfo initialThreadInfo) {
		this.handle = handle;
		this.moduleInfo = moduleInfo;
		this.initialThreadInfo = initialThreadInfo;
	}
}
