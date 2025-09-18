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

import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * The memory model of a target object
 * 
 * <p>
 * The convention for modeling valid addresses is to have children supporting
 * {@link TraceMemoryRegion}. If no such children exist, then the client should assume no address is
 * valid. Thus, for the client to confidently access any memory, at least one child region must
 * exist. It may present the memory's entire address space in a single region.
 */
@TraceObjectInfo(
	schemaName = "Memory",
	shortName = "memory",
	attributes = {},
	fixedKeys = {})
public interface TraceMemory extends TraceObjectInterface {
}
