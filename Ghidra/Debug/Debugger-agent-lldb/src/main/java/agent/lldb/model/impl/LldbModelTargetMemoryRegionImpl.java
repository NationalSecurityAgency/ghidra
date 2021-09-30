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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;

import SWIG.SBMemoryRegionInfo;
import SWIG.SBStream;
import agent.lldb.model.iface2.LldbModelTargetMemoryContainer;
import agent.lldb.model.iface2.LldbModelTargetMemoryRegion;
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
			type = LldbModelTargetMemoryContainerImpl.class),
		@TargetAttributeType(name = "RegionBase", type = Address.class),
		@TargetAttributeType(name = "RegionEnd", type = Address.class),
		@TargetAttributeType(name = "RegionSize", type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetMemoryRegionImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetMemoryRegion {

	protected static String keySection(SBMemoryRegionInfo region) {
		return PathUtils.makeKey(region.GetRegionBase().toString(16));
	}

	protected AddressRange range;
	protected List<String> protect;
	protected List<String> allocProtect;
	private boolean isRead;
	private boolean isWrite;
	private boolean isExec;

	public LldbModelTargetMemoryRegionImpl(LldbModelTargetMemoryContainer memory,
			SBMemoryRegionInfo region) {
		super(memory.getModel(), memory, keySection(region), region, "Region");

		this.changeAttributes(List.of(), List.of(), Map.of( //
			MEMORY_ATTRIBUTE_NAME, memory, //
			RANGE_ATTRIBUTE_NAME, range = doGetRange(region), //
			READABLE_ATTRIBUTE_NAME, region.IsReadable(), //
			WRITABLE_ATTRIBUTE_NAME, region.IsWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, region.IsExecutable() //
		), "Initialized");

		this.changeAttributes(List.of(), List.of(), Map.of( //
			"RegionBase", range.getMinAddress(), //
			"RegionEnd", range.getMaxAddress(), //
			"RegionSize", Long.toHexString(range.getMaxAddress().subtract(range.getMinAddress()) + 1) //
		), "Initialized");
	}

	@Override
	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBMemoryRegionInfo region = (SBMemoryRegionInfo) getModelObject();
		region.GetDescription(stream);
		return stream.GetData();
	}

	protected AddressRange doGetRange(SBMemoryRegionInfo s) {
		AddressSpace addressSpace = getModel().getAddressSpace("ram");
		Address min = addressSpace.getAddress(s.GetRegionBase().longValue());
		Address max = addressSpace.getAddress(s.GetRegionEnd().longValue() - 1);
		return max.getOffset() > min.getOffset() ? new AddressRangeImpl(min, max)
				: new AddressRangeImpl(min, min);
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

	public boolean isSame(SBMemoryRegionInfo section) {
		return range.equals(doGetRange(section));
	}

}
