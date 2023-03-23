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
package ghidra.app.plugin.core.debug.service.emulation.data;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.pcode.exec.trace.data.DefaultPcodeTracePropertyAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;

/**
 * The default trace-and-debugger-property access shim
 *
 * <p>
 * This implementation defers to the same property of mapped static images when the property is not
 * set in the trace.
 *
 * @param <T> the type of the property's values
 */
public class DefaultPcodeDebuggerPropertyAccess<T>
		extends DefaultPcodeTracePropertyAccess<T> {

	protected final InternalPcodeDebuggerDataAccess data;

	/**
	 * Construct the shim
	 * 
	 * @param data the trace-and-debugger-data access shim providing this property access shim
	 * @param name the name of the property
	 * @param type the type of the property
	 */
	protected DefaultPcodeDebuggerPropertyAccess(InternalPcodeDebuggerDataAccess data,
			String name, Class<T> type) {
		super(data, name, type);
		this.data = data;
	}

	@Override
	protected T whenNull(Address hostAddress) {
		DebuggerStaticMappingService mappingService =
			data.getTool().getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return super.whenNull(hostAddress);
		}
		ProgramLocation progLoc = mappingService.getOpenMappedLocation(new DefaultTraceLocation(
			data.getPlatform().getTrace(), null, Lifespan.at(data.getSnap()), hostAddress));
		if (progLoc == null) {
			return super.whenNull(hostAddress);
		}

		// NB. This is stored in the program, not the user data, despite what the name implies
		PropertyMap<?> map =
			progLoc.getProgram().getUsrPropertyManager().getPropertyMap(name);
		if (map == null) {
			return super.whenNull(hostAddress);
		}
		Object object = map.get(progLoc.getByteAddress());
		if (!type.isInstance(object)) {
			// TODO: Warn?
			return super.whenNull(hostAddress);
		}
		return type.cast(object);
	}
}
