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
package ghidra.program.model.pcode;

/**
 * This is an encoder that produces encodings that can be retroactively patched.
 * The contained encoding is expected to be byte based.  The user can record a position
 * in the encoding by calling the size() method in the middle of encoding, and then later
 * use the returned offset to call the patchIntegerAttribute() method and modify the
 * encoding at the recorded position.
 */
public interface PatchEncoder extends Encoder {

	/**
	 * Write a given raw spaceid (as returned by AddressSpace.getSpaceID()) as an attribute.
	 * The effect is the same as if writeSpace() was called with the AddressSpace matching
	 * the spaceid, i.e. the decoder will read this as just space attribute.
	 * @param attribId is the attribute
	 * @param spaceId is the given spaceid
	 */
	public void writeSpaceId(AttributeId attribId, long spaceId);

	/**
	 * The returned value can be used as a position for later modification
	 * @return the number of bytes written to this stream so far
	 */
	public int size();

	/**
	 * Replace an integer attribute for the element at the given position.
	 * The position is assumed to be at an open directive for the element containing the
	 * attribute to be patched.
	 * @param pos is the given position
	 * @param attribId is the attribute to be patched
	 * @param val is the new value to insert
	 * @return true if the attribute is successfully patched
	 */
	public boolean patchIntegerAttribute(int pos, AttributeId attribId, long val);
}
