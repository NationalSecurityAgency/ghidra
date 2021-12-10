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
package ghidra.app.util.bin.format.elf;

import javax.help.UnsupportedOperationException;

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.AbstractLeb128DataType;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;

/**
 * <code>AndroidElfRelocationOffset</code> provides a dynamic LEB128 relocation 
 * offset adjustment component for packed Android ELF Relocation Table groups.
 * See {@link AndroidElfRelocationGroup}.  The offset adjustment provided
 * by the LEB128 memory data is added to the associated baseOffset to obtain
 * the corresponding relocation offset/address.
 * <br>
 * Secondary purpose is to retain the relocation offset associated with a 
 * component instance.  This functionality relies on the 1:1 relationship
 * between this dynamic datatype and the single component which references it.
 */
class AndroidElfRelocationOffset extends AbstractLeb128DataType {

	private final long baseOffset;
	private long relocationOffset;

	/**
	 * Creates a packed relocation offset data type based upon a signed LEB128
	 * value adjusted by baseOffset.
	 * @param dtm the data type manager to associate with this data type.
	 * @param baseOffset base offset to which LEB128 offset data should be added
	 * @param relocationOffset the actual relocation offset value assciated with this
	 * instance (used by {@link #getValue(MemBuffer, Settings, int)} and 
	 * returned by {@link #getRelocationOffset()}.  This value should equals 
	 * <code>baseOffset</code> plus decoded value of sleb128 data.
	 */
	AndroidElfRelocationOffset(DataTypeManager dtm, long baseOffset, long relocationOffset) {
		super("sleb128_offset", true, dtm);
		this.baseOffset = baseOffset;
		this.relocationOffset = relocationOffset;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		// specific instances are used by AndroidElfRelocationGroup
		throw new UnsupportedOperationException("may not be cloned");
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public String getDescription() {
		return "Android Packed Relocation Offset for ELF";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "sleb128";
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return null;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	private long getImageBaseAdjustment(Program program) {
		Long originalimageBase = ElfLoader.getElfOriginalImageBase(program);
		if (originalimageBase != null) {
			return program.getImageBase().getOffset() - originalimageBase;
		}
		return 0;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		Scalar s = (Scalar) super.getValue(buf, settings, length);
		if (s == null) {
			return null;
		}
		long imageBaseAdj = 0;
		Memory mem = buf.getMemory();
		if (mem != null) {
			imageBaseAdj = getImageBaseAdjustment(mem.getProgram());
		}

		// assume pointer into physical space associated with buf
		AddressSpace space = buf.getAddress().getAddressSpace().getPhysicalSpace();
		return space.getAddress(s.getSignedValue() + baseOffset + imageBaseAdj);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Scalar s = (Scalar) super.getValue(buf, settings, length);
		if (s == null) {
			return "??";
		}
		// TODO: not sure what representation to use
		StringBuilder b = new StringBuilder();
		if (baseOffset != 0) {
			b.append("0x");
			b.append(Long.toHexString(baseOffset));
			b.append(" + ");
		}
		b.append("0x");
		b.append(Long.toHexString(s.getSignedValue()));
		return b.toString();
	}

	/**
	 * Get the stashed relocation offset associated with this data item
	 * @return the relocation offset associated with this data item
	 */
	long getRelocationOffset() {
		return relocationOffset;
	}

}
