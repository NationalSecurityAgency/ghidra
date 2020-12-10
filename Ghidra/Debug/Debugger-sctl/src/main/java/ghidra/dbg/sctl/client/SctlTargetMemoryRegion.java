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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.Map;

import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

public class SctlTargetMemoryRegion extends DefaultTargetObject<TargetObject, SctlTargetMemory>
		implements TargetMemoryRegion<SctlTargetMemoryRegion> {
	protected static final String FILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "file";

	protected static String keyRegion(Address address) {
		return PathUtils.makeKey(indexRegion(address));
	}

	protected static String indexRegion(Address address) {
		return address.toString();
	}

	protected final SctlClient client;

	protected final String file;
	protected final AddressRange range;
	protected final BitmaskSet<SctlMemoryProtection> protections;

	public SctlTargetMemoryRegion(SctlTargetMemory memory, String file, Address address,
			long length, BitmaskSet<SctlMemoryProtection> protections)
			throws AddressOverflowException {
		super(memory.client, memory, keyRegion(address), "MemoryRegion");
		this.client = memory.client;

		this.file = file;
		this.range = new AddressRangeImpl(address, address.addNoWrap(length - 1));
		this.protections = protections;

		changeAttributes(List.of(), Map.of( //
			FILE_ATTRIBUTE_NAME, file, //
			RANGE_ATTRIBUTE_NAME, range, //
			READABLE_ATTRIBUTE_NAME, isReadable(), //
			WRITABLE_ATTRIBUTE_NAME, isWritable(), //
			EXECUTABLE_ATTRIBUTE_NAME, isExecutable() //
		), "Initialized");
	}

	@Override
	public String getDisplay() {
		if (file != null) {
			return range.getMinAddress() + " (" + file + ")";
		}
		return range.getMinAddress().toString();
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	public String getFile() {
		return file;
	}

	@Override
	public boolean isReadable() {
		return protections.contains(SctlMemoryProtection.PROT_READ);
	}

	@Override
	public boolean isWritable() {
		return protections.contains(SctlMemoryProtection.PROT_WRITE);
	}

	@Override
	public boolean isExecutable() {
		return protections.contains(SctlMemoryProtection.PROT_EXEC);
	}
}
