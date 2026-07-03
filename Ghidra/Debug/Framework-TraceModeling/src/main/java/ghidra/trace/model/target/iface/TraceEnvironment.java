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
 * Provides information about a given target object
 * 
 * <p>
 * This is mostly a marker interface so that the client knows where to look for information about a
 * target. This may be attached to the entire session, or it may be attached to individual targets
 * in a session. The information is generally encoded as string-valued attributes. The form of the
 * strings is not strictly specified. They should generally just take verbatim whatever string the
 * connected debugger would use to describe the platform. It is up to the client to interpret the
 * information.
 */
@TraceObjectInfo(
	schemaName = "Environment",
	shortName = "environment",
	attributes = {
		TraceEnvironment.KEY_ARCH,
		TraceEnvironment.KEY_DEBUGGER,
		TraceEnvironment.KEY_ENDIAN,
		TraceEnvironment.KEY_OS,
	},
	fixedKeys = {})
public interface TraceEnvironment extends TraceObjectInterface {
	String KEY_ARCH = "_arch";
	String KEY_DEBUGGER = "_debugger";
	String KEY_ENDIAN = "_endian";
	String KEY_OS = "_os";

	// LATER?: Devices, File System
}
