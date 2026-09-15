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
package ghidra.trace.model.thread;

import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.target.iface.TraceExecutionStateful;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * A marker interface which indicates a process, usually on a host operating system
 * 
 * <p>
 * If this object does not support {@link TraceExecutionStateful}, then its mere existence in
 * the model implies that it is {@link TraceExecutionState#ALIVE}. TODO: Should allow association
 * via convention to a different {@link TraceExecutionStateful}, but that may have to wait
 * until schemas are introduced.
 */
@TraceObjectInfo(
	schemaName = "Process",
	shortName = "process",
	attributes = {
		TraceProcess.KEY_PID,
	},
	fixedKeys = {})
public interface TraceProcess extends TraceObjectInterface {
	String KEY_PID = "_pid";
}
