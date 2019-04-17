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
package ghidra.feature.fid.hash;

/**
 * Container to hold all three hashes for a function (medium, full, and specific).
 */
public interface FidHashQuad {

	/**
	 * Returns the actual number of code units used to compute the full hash value.
	 * @return the number of code units for the full hash
	 */
	public short getCodeUnitSize();

	/**
	 * Returns the full hash value.
	 * @return the full hash value
	 */
	public long getFullHash();

	/**
	 * Returns the ADDITIONAL number of code units, past the number used for the full hash,
	 * used to compute the specific hash value.
	 * @return the ADDITIONAL number of code units for the specific hash
	 */
	public byte getSpecificHashAdditionalSize();

	/**
	 * Returns the specific hash value.
	 * @return the specific hash value
	 */
	public long getSpecificHash();
}
