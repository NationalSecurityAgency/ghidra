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
package ghidra.trace.model.target.iface;

import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * An object that can emit events affecting itself and its successors
 * 
 * <p>
 * If this is present, it must be on the root object.
 */
@TraceObjectInfo(
	schemaName = "EventScope",
	shortName = "event scope",
	attributes = {
		TraceObjectEventScope.KEY_EVENT_THREAD,
	},
	fixedKeys = {})
public interface TraceObjectEventScope extends TraceObjectInterface {
	String KEY_EVENT_THREAD = "_event_thread";
}
