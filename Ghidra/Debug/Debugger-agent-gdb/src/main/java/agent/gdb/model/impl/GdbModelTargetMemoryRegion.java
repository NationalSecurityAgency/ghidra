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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.impl.GdbMemoryMapping;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "MemoryRegion",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetMemoryRegion
		extends DefaultTargetObject<TargetObject, GdbModelTargetProcessMemory>
		implements TargetMemoryRegion {
	protected static final String OBJFILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "objfile";
	protected static final String OFFSET_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "offset";

	protected static String indexRegion(GdbMemoryMapping mapping) {
		return mapping.getStart().toString(16);
	}

	protected static String keyRegion(GdbMemoryMapping mapping) {
		return PathUtils.makeKey(indexRegion(mapping));
	}

	protected static String computeDisplay(GdbMemoryMapping mapping) {
		// NOTE: This deviates from GDB's table display, as it'd be confusing in isolation
		if (mapping.getObjfile() == null || mapping.getObjfile().length() == 0) {
			return String.format("?? [0x%x-0x%x]", mapping.getStart(), mapping.getEnd());
		}
		return String.format("%s [0x%x-0x%x] (0x%x)", mapping.getObjfile(), mapping.getStart(),
			mapping.getEnd(), mapping.getOffset());
	}

	protected AddressRangeImpl range;
	protected final String objfile;
	protected final long offset;
	protected final String display;

	public GdbModelTargetMemoryRegion(GdbModelTargetProcessMemory memory,
			GdbMemoryMapping mapping) {
		super(memory.impl, memory, keyRegion(mapping), "MemoryRegion");
		memory.impl.addModelObject(mapping, this);
		try {
			Address min = memory.impl.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(mapping.getStart().toString(16));
			this.range = new AddressRangeImpl(min, mapping.getSize().longValue());
		}
		catch (AddressFormatException | AddressOverflowException e) {
			throw new AssertionError(e);
		}
		changeAttributes(List.of(), Map.of( //
			MEMORY_ATTRIBUTE_NAME, memory, //
			RANGE_ATTRIBUTE_NAME, range, //
			READABLE_ATTRIBUTE_NAME, isReadable(), //
			WRITABLE_ATTRIBUTE_NAME, isWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, isExecutable(), //
			OBJFILE_ATTRIBUTE_NAME, objfile = mapping.getObjfile(), //
			OFFSET_ATTRIBUTE_NAME, offset = mapping.getOffset().longValue(), //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(mapping) //
		), "Initialized");
	}

	protected boolean isSame(GdbMemoryMapping mapping) {
		// Hacky, but effective
		// TODO: Check/update permissions?
		return display.equals(computeDisplay(mapping));
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public GdbModelTargetProcessMemory getMemory() {
		return parent;
	}

	@Override
	public boolean isReadable() {
		// It can be done if debugging locally on Linux, by reading /proc/[PID]/maps
		// The sections listing will give the initial protections.
		return true; // TODO
	}

	@Override
	public boolean isWritable() {
		return true; // TODO
	}

	@Override
	public boolean isExecutable() {
		return true; // TODO
	}

	@TargetAttributeType(
		name = OBJFILE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	public String getObjfile() {
		return objfile;
	}

	@TargetAttributeType(
		name = OFFSET_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	public long getOffset() {
		return offset;
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		// Nothing to do here
		return AsyncUtils.NIL;
	}
}
