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

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.iface.TraceObjectExecutionStateful;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * A marker interface which indicates a thread, usually within a process
 * 
 * <p>
 * This object must be associated with a suitable {@link TraceObjectExecutionStateful}. In most
 * cases, the object should just implement it.
 */
@TraceObjectInfo(
	schemaName = "Thread",
	shortName = "thread",
	attributes = {
		TraceObjectThread.KEY_TID,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectInterface.KEY_COMMENT,
	})
public interface TraceObjectThread extends TraceThread, TraceObjectInterface {
	String KEY_TID = "_tid";

	void setName(Lifespan lifespan, String name);
}
