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

public interface BitFieldPacking {

	/**
	 * Control if the alignment and packing of bit-fields follows MSVC conventions.  
	 * When this is enabled it takes precedence over all other bitfield packing controls.
	 * @return true if MSVC packing conventions are used, else false (e.g., GNU conventions apply).
	 */
	boolean useMSConvention();

	/**
	 * Control whether the alignment of bit-field types is respected when laying out structures.
	 * Corresponds to PCC_BITFIELD_TYPE_MATTERS in GCC.
	 * @return true when the alignment of the bit-field type should be used to impact the 
	 * alignment of the containing structure, and ensure that individual bit-fields will not 
	 * straddle an alignment boundary. 
	 */
	boolean isTypeAlignmentEnabled();

	/**
	 * A non-zero value indicates the fixed alignment size for bit-fields which follow
	 * a zero-length bitfield if greater than a bitfields base type normal alignment. 
	 * Corresponds to EMPTY_FIELD_BOUNDARY in GCC.
	 * This value is only used when {@link #isTypeAlignmentEnabled()} returns false.
	 * @return fixed alignment size as number of bytes for a bit-field which follows
	 * a zero-length bit-field
	 */
	int getZeroLengthBoundary();
}
