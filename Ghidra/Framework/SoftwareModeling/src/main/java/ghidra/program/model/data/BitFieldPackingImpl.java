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
package ghidra.program.model.data;

public class BitFieldPackingImpl implements BitFieldPacking {

	private boolean useMSConvention = false;
	private boolean typeAlignmentEnabled = true;
	private int zeroLengthBoundary = 0;

	@Override
	public boolean useMSConvention() {
		return useMSConvention;
	}

	@Override
	public boolean isTypeAlignmentEnabled() {
		return useMSConvention || typeAlignmentEnabled; // same as PCC_BITFIELD_TYPE_MATTERS
	}

	@Override
	public int getZeroLengthBoundary() {
		return useMSConvention ? 0 : zeroLengthBoundary;
	}

	/**
	 * Control if the alignment and packing of bit-fields follows MSVC conventions.  
	 * When this is enabled it takes precedence over all other bitfield packing controls.
	 * @param useMSConvention true if MSVC packing conventions are used, else false (e.g., GNU conventions apply).
	 */
	public void setUseMSConvention(boolean useMSConvention) {
		this.useMSConvention = useMSConvention;
	}

	/**
	 * Control whether the alignment of bit-field types is respected when laying out structures.
	 * Corresponds to PCC_BITFIELD_TYPE_MATTERS in gcc.
	 * @param typeAlignmentEnabled true if the alignment of the bit-field type should be used
	 * to impact the alignment of the containing structure, and ensure that individual bit-fields 
	 * will not straddle an alignment boundary. 
	 */
	public void setTypeAlignmentEnabled(boolean typeAlignmentEnabled) {
		this.typeAlignmentEnabled = typeAlignmentEnabled;
	}

	/**
	 * Indicate a fixed alignment size in bytes which should be used for zero-length bit-fields.
	 * @param zeroLengthBoundary fixed alignment size as number of bytes for a bit-field 
	 * which follows a zero-length bit-field.  A value of 0 causes zero-length type size to be used.
	 */
	public void setZeroLengthBoundary(int zeroLengthBoundary) {
		this.zeroLengthBoundary = zeroLengthBoundary;
	}

}
