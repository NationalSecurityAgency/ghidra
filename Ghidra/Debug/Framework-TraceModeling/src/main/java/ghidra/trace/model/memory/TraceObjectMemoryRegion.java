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
package ghidra.trace.model.memory;

import java.util.Collection;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

@TraceObjectInfo(
	schemaName = "MemoryRegion",
	shortName = "region",
	attributes = {
		TraceObjectMemoryRegion.KEY_RANGE,
		TraceObjectMemoryRegion.KEY_READABLE,
		TraceObjectMemoryRegion.KEY_WRITABLE,
		TraceObjectMemoryRegion.KEY_EXECUTABLE,
		TraceObjectMemoryRegion.KEY_VOLATILE,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectMemoryRegion.KEY_RANGE,
	})
public interface TraceObjectMemoryRegion extends TraceMemoryRegion, TraceObjectInterface {
	String KEY_RANGE = "_range";
	String KEY_READABLE = "_readable";
	String KEY_WRITABLE = "_writable";
	String KEY_EXECUTABLE = "_executable";
	String KEY_VOLATILE = "_volatile";

	void setName(Lifespan lifespan, String name);

	void setRange(Lifespan lifespan, AddressRange range);

	AddressRange getRange(long snap);

	Address getMinAddress(long snap);

	Address getMaxAddress(long snap);

	void setFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	void addFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	void clearFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags);

	Set<TraceMemoryFlag> getFlags(long snap);
}
