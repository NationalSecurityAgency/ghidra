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
package ghidra.app.services;

import java.util.Set;

import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

public interface DebuggerStaticMappingChangeListener {
	/**
	 * The mappings among programs and traces open in this tool have changed
	 * 
	 * <p>
	 * TODO: Consider more precise callbacks: added, removed for each MappingEntry? One reason is
	 * that this callback is hit no matter the snap(s) of the affected entries. It could be a
	 * listeners is only interested in a particular snap, and could duly ignore some callbacks if
	 * precise information was provided.
	 * 
	 * @param affectedTraces the set of traces affected by the change(s)
	 * @param affectedPrograms the set of programs affected by the change(s)
	 */
	void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms);
}
