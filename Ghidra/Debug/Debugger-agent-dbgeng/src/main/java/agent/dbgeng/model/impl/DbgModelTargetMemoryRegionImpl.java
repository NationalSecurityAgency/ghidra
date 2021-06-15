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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;

import agent.dbgeng.manager.DbgModuleMemory;
import agent.dbgeng.model.iface2.DbgModelTargetMemoryContainer;
import agent.dbgeng.model.iface2.DbgModelTargetMemoryRegion;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "MemoryRegion",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = TargetMemoryRegion.MEMORY_ATTRIBUTE_NAME,
			type = DbgModelTargetMemoryContainerImpl.class),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "EndAddress", type = Address.class),
		@TargetAttributeType(name = "RegionSize", type = String.class),
		@TargetAttributeType(name = "AllocationBase", type = Address.class),
		@TargetAttributeType(name = "AllocationProtect", type = String.class),
		@TargetAttributeType(name = "Protect", type = String.class),
		@TargetAttributeType(name = "State", type = String.class),
		@TargetAttributeType(name = "Type", type = String.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetMemoryRegionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetMemoryRegion {

	protected static String indexSection(DbgModuleMemory section) {
		return section.getName();
	}

	protected static String keySection(DbgModuleMemory section) {
		return PathUtils.makeKey(indexSection(section));
	}

	protected final DbgModuleMemory section;
	protected final AddressRange range;
	protected final List<String> protect;
	protected final List<String> allocProtect;
	private boolean isRead;
	private boolean isWrite;
	private boolean isExec;

	public DbgModelTargetMemoryRegionImpl(DbgModelTargetMemoryContainer memory,
			DbgModuleMemory region) {
		super(memory.getModel(), memory, keySection(region), "Region");
		this.getModel().addModelObject(region, this);
		this.section = region;

		this.range = doGetRange(section);
		allocProtect = region.getAllocationProtect();
		String apx = "";
		for (String p : allocProtect) {
			apx += p + ":";
		}
		if (apx.length() > 1) {
			apx = apx.substring(0, apx.length() - 1);
		}
		protect = region.getProtect();
		String ipx = "";
		for (String p : protect) {
			ipx += p + ":";
		}
		if (ipx.length() > 1) {
			ipx = ipx.substring(0, ipx.length() - 1);
		}
		isRead = region.isRead();
		isWrite = region.isWrite();
		isExec = region.isExec();

		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, computeDisplay(region), //
			MEMORY_ATTRIBUTE_NAME, memory, //
			RANGE_ATTRIBUTE_NAME, doGetRange(section), //
			READABLE_ATTRIBUTE_NAME, isReadable(), //
			WRITABLE_ATTRIBUTE_NAME, isWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, isExecutable() //
		), "Initialized");

		AddressSpace space = getModel().getAddressSpace("ram");
		this.changeAttributes(List.of(), List.of(), Map.of( //
			"BaseAddress", space.getAddress(region.getVmaStart()), //
			"EndAddress", space.getAddress(region.getVmaEnd()), //
			"RegionSize", Long.toHexString(region.getVmaEnd() - region.getVmaStart()), //
			"AllocationBase", space.getAddress(region.getAllocationBase()), //
			"AllocationProtect", apx, //
			"Protect", ipx, //
			"State", region.getState(), //
			"Type", region.getType() //
		), "Initialized");
	}

	protected String computeDisplay(DbgModuleMemory region) {
		return region.getType() + " " + getName(); // NB. Name will contain []s
	}

	protected AddressRange doGetRange(DbgModuleMemory s) {
		AddressSpace addressSpace = getModel().getAddressSpace("ram");
		Address min = addressSpace.getAddress(s.getVmaStart());
		Address max = addressSpace.getAddress(s.getVmaEnd() - 1);
		return new AddressRangeImpl(min, max);
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

	public boolean isSame(DbgModuleMemory section) {
		return range.equals(doGetRange(section));
	}

}
