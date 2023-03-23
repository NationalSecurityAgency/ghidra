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
package ghidra.file.formats.dump;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;

public class DumpData {

	private DataType dt;
	private long offset;
	private String name;
	private boolean generateSymbol;
	private boolean generateFragment;
	private long size;
	private AddressSpace space;

	public DumpData(long offset, DataType dt) {
		this(offset, dt, dt.getDisplayName(), false, true);
	}

	public DumpData(long offset, DataType dt, String name) {
		this(offset, dt, name, true, true);
	}

	public DumpData(long offset, DataType dt, String name, boolean genSymbol, boolean genFragment) {
		this.offset = offset;
		this.dt = dt;
		this.name = name;
		this.generateSymbol = genSymbol;
		this.generateFragment = genFragment;
		this.size = dt.getLength();
	}

	public DumpData(long offset, String name, int size) {
		this.offset = offset;
		this.dt = null;
		this.name = name;
		this.generateSymbol = true;
		this.generateFragment = true;
		this.size = size;
	}

	public DataType getDataType() {
		return dt;
	}

	public void setDataType(DataType dt) {
		this.dt = dt;
	}

	public long getOffset() {
		return offset;
	}

	public void setOffset(long offset) {
		this.offset = offset;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public boolean isGenerateSymbol() {
		return generateSymbol;
	}

	public void setGenerateSymbol(boolean genSymbol) {
		this.generateSymbol = genSymbol;
	}

	public boolean isGenerateFragment() {
		return generateFragment;
	}

	public void setGenerateFragment(boolean genFragment) {
		this.generateFragment = genFragment;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public long getSize() {
		return size;
	}

	public AddressSpace getAddressSpace() {
		return space;
	}

	public void setAddressSpace(AddressSpace space) {
		this.space = space;
	}
}
