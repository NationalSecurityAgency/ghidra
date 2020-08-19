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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of VT Shaped type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class VtShapeMsType extends AbstractMsType {

	public static final int PDB_ID = 0x000a;

	private int count; // Number of entries in the VFT.
	private List<VtShapeDescriptorMsProperty> descriptorList = new ArrayList<>();

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public VtShapeMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		count = reader.parseUnsignedShortVal();
		int byteVal = 0;
		int value;
		VtShapeDescriptorMsProperty descriptor;
		// It seems that the upper nibble of the the byte is first and the lower nibble is
		//  second; that is why we process as we do below (shifting for the first and masking
		//  for the second).
		for (int i = 0; i < count / 2; i++) {
			byteVal = reader.parseUnsignedByteVal();
			value = byteVal >> 4;
			descriptor = VtShapeDescriptorMsProperty.fromValue(value);
			descriptorList.add(descriptor);
			value = byteVal & 0x0f;
			descriptor = VtShapeDescriptorMsProperty.fromValue(value);
			descriptorList.add(descriptor);
		}
		if (count % 2 == 1) {
			byteVal = reader.parseUnsignedByteVal();
			value = byteVal >> 4;
			descriptor = VtShapeDescriptorMsProperty.fromValue(value);
			descriptorList.add(descriptor);
		}
		reader.skipPadding();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the count of elements.
	 * @return the count.
	 */
	public int getCount() {
		return count;
	}

	/**
	 * Returns the descriptor list for the shape.
	 * @return the descriptor list.
	 */
	public List<VtShapeDescriptorMsProperty> getDescriptorList() {
		return descriptorList;
	}

	/**
	 * Tells whether the the {@link VtShapeDescriptorMsProperty} is present.
	 * @param descriptor the {@link VtShapeDescriptorMsProperty} to check.
	 * @return True if the {@link VtShapeDescriptorMsProperty} is present.
	 */
	public boolean hasDescriptor(VtShapeDescriptorMsProperty descriptor) {
		return descriptorList.contains(descriptor);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		// No documented API for output.
		DelimiterState ds = new DelimiterState("", ",");
		builder.append("vtshape: {");
		for (VtShapeDescriptorMsProperty descriptor : descriptorList) {
			builder.append(ds.out(true, descriptor));
		}
		builder.append("}");
	}

}
