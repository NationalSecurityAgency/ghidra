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

import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.info.TraceObjectInfo;
import ghidra.trace.model.thread.TraceThread;

/**
 * A common interface for object-based implementations of other trace manager entries, e.g.,
 * {@link TraceThread}.
 */
@TraceObjectInfo(
	schemaName = "OBJECT",
	shortName = "object",
	attributes = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectInterface.KEY_COMMENT,
	},
	fixedKeys = {})
public interface TraceObjectInterface {
	String KEY_DISPLAY = "_display";
	String KEY_SHORT_DISPLAY = "_short_display";
	String KEY_KIND = "_kind";
	String KEY_ORDER = "_order";

	// TODO: Should these belong to some Value interface?
	String KEY_MODIFIED = "_modified";
	String KEY_TYPE = "_type";
	String KEY_VALUE = "_value";
	String KEY_COMMENT = "_comment";

	/**
	 * Get the object backing this implementation
	 * 
	 * @return the object
	 */
	TraceObject getObject();
}
