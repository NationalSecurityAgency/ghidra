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
package ghidra.app.util.bin.format.dwarf.external;

import ghidra.util.task.TaskMonitor;

/**
 * Base interface for objects that can provide DWARF debug files.  See {@link DebugFileProvider} or
 * {@link DebugStreamProvider}.
 */
public interface DebugInfoProvider {
	/**
	 * {@return the name of this instance, which should be a serialized copy of this instance, 
	 * typically like "something://serialized_data"}
	 */
	String getName();

	/**
	 * {@return a human formatted string describing this provider, used in UI prompts or lists}
	 */
	String getDescriptiveName();

	/**
	 * {@return DebugInfoProviderStatus representing this provider's current status} 
	 * @param monitor {@link TaskMonitor}
	 */
	DebugInfoProviderStatus getStatus(TaskMonitor monitor);
}
