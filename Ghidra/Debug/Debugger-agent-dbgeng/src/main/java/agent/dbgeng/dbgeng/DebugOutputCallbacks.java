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

import agent.dbgeng.dbgeng.DebugControl.DebugOutputLevel;

/**
 * The interface for receiving output callbacks via {@code IDebugOutputCallbacks} or a newer
 * variant.
 * 
 * Note: The wrapper implementation will select the apprirate native interface version.
 * 
 * TODO: Change {@link #output(int, String)} {@code mask} parameter to use {@link DebugOutputLevel}
 * flags.
 */
@FunctionalInterface
public interface DebugOutputCallbacks {
	void output(int mask, String text);
}
