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
 * An opaque handle identifying a library
 * 
 * GDB leaves a lot of variability in how libraries are uniquely identified within an inferior. This
 * interface provides a means for an implementor to define it arbitrarily. It seems GDB actually
 * uses the path of the library, but one should not depend on it.
 */
public interface GdbLibraryId {
	// An opaque handle
}
