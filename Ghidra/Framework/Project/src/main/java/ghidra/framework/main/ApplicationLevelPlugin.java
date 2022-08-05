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
package ghidra.framework.main;

/**
 * Marker that signals the implementing plugin can be added to the system at the application level.
 * <p>
 * Some applications have only a single tool while other applications may have multiple tools, with
 * a top-level tool that manages other sub-tools.  A plugin implementing this interface can be used
 * in any of these tools.
 */
public interface ApplicationLevelPlugin {
	// marker interface
}
