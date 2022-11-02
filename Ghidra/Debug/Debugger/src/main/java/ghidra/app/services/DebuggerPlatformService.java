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

import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

/**
 * A service to manage the current mapper for active traces
 */
public interface DebuggerPlatformService {

	/**
	 * Get the current mapper for the given trace
	 * 
	 * @param trace the trace
	 * @return the mapper, or null
	 */
	DebuggerPlatformMapper getCurrentMapperFor(Trace trace);

	/**
	 * Get a mapper applicable to the given object
	 * 
	 * <p>
	 * If the trace's current mapper is applicable to the object, it will be returned. Otherwise,
	 * the service will query the opinions for a new mapper, as in
	 * {@link #getNewMapper(TraceObject)} and set it as the current mapper before returning. If a
	 * new mapper is set, the trace is also initialized for that mapper.
	 * 
	 * @param trace the trace
	 * @param object the object for which a mapper is desired
	 * @param snap the snap, usually the current snap
	 * @return the mapper, or null if no offer was provided
	 */
	DebuggerPlatformMapper getMapper(Trace trace, TraceObject object, long snap);

	/**
	 * Get a new mapper for the given object, ignoring the trace's current mapper
	 * 
	 * <p>
	 * This will not replace the trace's current mapper, nor will it initialize the trace for the
	 * mapper.
	 * 
	 * @param trace the trace
	 * @param object the object for which a mapper is desired
	 * @param snap the snap, usually the current snap
	 * @return the mapper, or null if no offer was provided
	 */
	DebuggerPlatformMapper getNewMapper(Trace trace, TraceObject object, long snap);

	/**
	 * Set the current mapper for the trace and initialize the trace for the mapper
	 * 
	 * @param trace the trace whose current mapper to set
	 * @param mapper the mapper
	 * @param snap the snap for initializing the trace
	 */
	void setCurrentMapperFor(Trace trace, DebuggerPlatformMapper mapper, long snap);
}
