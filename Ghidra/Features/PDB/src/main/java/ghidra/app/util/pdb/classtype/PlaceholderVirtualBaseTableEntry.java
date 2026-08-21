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
public class PlaceholderVirtualBaseTableEntry extends VirtualBaseTableEntry {
	private Long offset;

	// Re-evaluate which constructors and setters we need

	public PlaceholderVirtualBaseTableEntry(Long offset) {
		this(offset, null);
	}

	public PlaceholderVirtualBaseTableEntry(ClassID baseId) {
		this(null, baseId);
	}

	public PlaceholderVirtualBaseTableEntry(Long offset, ClassID baseId) {
		super(baseId);
		this.offset = offset;
	}

	public void setOffset(Long offset) {
		this.offset = offset;
	}

	public Long getOffset() {
		return offset;
	}

	//==============================================================================================
	// Info from longer-running branch

	void emit(StringBuilder builder, long vbtPtrOffset) {
//		emitLine(builder, offset, vbtPtrOffset,
//			getClassId(compiledBaseClass, baseClassComponent).toString());
		emitLine(builder, getOffset(), vbtPtrOffset, getClassId().toString());
	}

	static void emitHeader(StringBuilder builder, long ownerOffset, long vbtPtrOffset) {
		builder.append(String.format("%-10s %-10s %-10s\n", "OffInOwner", "OffFromPtr", "Base"));
		emitLine(builder, ownerOffset, vbtPtrOffset, "'ForClass'");
	}

	static void emitLine(StringBuilder builder, long classOffset, long vbtPtrOffset, String owner) {
		builder.append(
			String.format("%-10d %-10d %-10s\n", classOffset, classOffset - vbtPtrOffset, owner));
	}

}
