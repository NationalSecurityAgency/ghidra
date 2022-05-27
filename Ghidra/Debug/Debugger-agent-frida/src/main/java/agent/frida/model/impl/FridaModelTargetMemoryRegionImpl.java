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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.manager.FridaMemoryRegionInfo;
import agent.frida.model.iface2.FridaModelTargetMemoryContainer;
import agent.frida.model.iface2.FridaModelTargetMemoryRegion;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;

@TargetObjectSchemaInfo(
	name = "MemoryRegion",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
				name = TargetMemoryRegion.MEMORY_ATTRIBUTE_NAME,
				type = FridaModelTargetMemoryContainerImpl.class),
		@TargetAttributeType(
				name = "File",
				type = FridaModelTargetFileSpecImpl.class),
		@TargetAttributeType(name = "RegionBase", type = Address.class),
		@TargetAttributeType(name = "RegionEnd", type = Address.class),
		@TargetAttributeType(name = "RegionSize", type = String.class),
		@TargetAttributeType(name = "Protection", type = String.class),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetMemoryRegionImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetMemoryRegion {

	protected static String keySection(FridaMemoryRegionInfo region) {
		return PathUtils.makeKey(region.getRangeAddress());
	}

	protected AddressRange range;
	protected List<String> protect;
	protected List<String> allocProtect;
	private boolean isRead;
	private boolean isWrite;
	private boolean isExec;
	private FridaModelTargetFileSpecImpl fileSpec;

	public FridaModelTargetMemoryRegionImpl(FridaModelTargetMemoryContainer memory,
			FridaMemoryRegionInfo region) {
		super(memory.getModel(), memory, keySection(region), region, "Region");

		this.isRead = region.isReadable();
		this.isWrite = region.isWritable();
		this.isExec = region.isExecutable();
		this.changeAttributes(List.of(), List.of(), Map.of( //
			MEMORY_ATTRIBUTE_NAME, memory, //
			READABLE_ATTRIBUTE_NAME, isRead, //
			WRITABLE_ATTRIBUTE_NAME, isWrite, //
			EXECUTABLE_ATTRIBUTE_NAME, isExec, //
			"Protection", region.getProtection() //
		), "Initialized");

		range = doGetRange(region);
		if (range != null) {
			this.changeAttributes(List.of(), List.of(), Map.of( //
				RANGE_ATTRIBUTE_NAME, range, //
				"RegionBase", range.getMinAddress(), //
				"RegionEnd", range.getMaxAddress(), //
				"RegionSize", Long.toHexString(range.getMaxAddress().subtract(range.getMinAddress()) + 1) //
			), "Initialized");
		}
		
		if (region.getFileSpec() != null) {
			this.fileSpec = new FridaModelTargetFileSpecImpl(this, region.getFileSpec());
			this.changeAttributes(List.of(), List.of(), Map.of( //
				"File", fileSpec //
			), "Initialized");
		}
		
	}

	protected AddressRange doGetRange(FridaMemoryRegionInfo s) {
		try {
			AddressSpace addressSpace = getModel().getAddressSpace("ram");
			Address min = addressSpace.getAddress(s.getRangeAddress());
			Address max = min.add(s.getRangeSize() - 1);
			return max.getOffset() > min.getOffset() ? new AddressRangeImpl(min, max)
					: new AddressRangeImpl(min, min);
		} catch (AddressFormatException e) {
			return null;
		}
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	@Override
	public boolean isReadable() {
		return isRead;
	}

	@Override
	public boolean isWritable() {
		return isWrite;
	}

	@Override
	public boolean isExecutable() {
		return isExec;
	}

	public boolean isSame(FridaMemoryRegionInfo section) {
		return range.equals(doGetRange(section));
	}

}
