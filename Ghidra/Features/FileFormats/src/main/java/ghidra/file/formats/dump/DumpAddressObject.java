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

import ghidra.program.model.address.Address;

public class DumpAddressObject {

	private String providerId;
	private long rva;
	private long base;
	private long length;
	private boolean isRead = true;
	private boolean isWrite = true;
	private boolean isExec = true;
	private String comment;
	private Address address;
	private String rangeName;

	public DumpAddressObject(String providerId, long rva, long base, long length) {
		this.providerId = providerId;
		this.rva = rva;
		this.base = base;
		this.length = length;
	}

	public String getProviderId() {
		return providerId;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}

	public long getRVA() {
		return rva;
	}

	public void setRVA(long rva) {
		this.rva = rva;
	}

	public long getBase() {
		return base;
	}

	public void setBase(long base) {
		this.base = base;
	}

	public void setLength(long length) {
		this.length = length;
	}

	public long getLength() {
		return length;
	}

	public long getAdjustedAddress(long addr) {
		return addr - getBase() + getRVA();
	}

	public long getCopyLen(long addr, long size) {
		if (addr - getRVA() + size > getLength()) {
			return getLength() - (addr - getRVA());
		}
		return size;
	}

	public boolean isRead() {
		return isRead;
	}

	public boolean isWrite() {
		return isWrite;
	}

	public boolean isExec() {
		return isExec;
	}

	public void setRead(boolean isRead) {
		this.isRead = isRead;
	}

	/**
	 * @param isWrite the isWrite to set
	 */
	public void setWrite(boolean isWrite) {
		this.isWrite = isWrite;
	}

	/**
	 * @param isExec the isExec to set
	 */
	public void setExec(boolean isExec) {
		this.isExec = isExec;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public String getRangeName() {
		return rangeName;
	}

	public void setRangeName(String name) {
		this.rangeName = name;
	}

}
