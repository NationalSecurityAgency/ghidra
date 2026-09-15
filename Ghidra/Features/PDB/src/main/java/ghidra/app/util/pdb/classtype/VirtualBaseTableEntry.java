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

import ghidra.program.model.gclass.ClassID;

/**
 * Represents the Entry for a Virtual Base Table
 */
public class VirtualBaseTableEntry implements VBTableEntry {
	private ClassID baseId;

	// Re-evaluate which constructors and setters we need

	public VirtualBaseTableEntry(ClassID baseId) {
		this.baseId = baseId;
	}

	@Override
	public void setClassId(ClassID baseId) {
		this.baseId = baseId;
	}

	@Override
	public ClassID getClassId() {
		return baseId;
	}
}
