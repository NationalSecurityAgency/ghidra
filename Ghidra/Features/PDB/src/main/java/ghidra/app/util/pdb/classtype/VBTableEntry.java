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
package ghidra.app.util.pdb.classtype;

/**
 * Represents an entry within a virtual base table
 */
public interface VBTableEntry {

	/**
	 * Sets the entry offset value
	 * @param offset the offset
	 */
	public void setOffset(long offset);

	/**
	 * Gets the entry offset value
	 * @return the offset value
	 */
	public Long getOffset();

	/**
	 * Sets the entry class ID
	 * @param baseId the ID
	 */
	public void setClassId(ClassID baseId);

	/**
	 * Gets the entry class ID
	 * @return the ID
	 */
	public ClassID getClassId();

}
