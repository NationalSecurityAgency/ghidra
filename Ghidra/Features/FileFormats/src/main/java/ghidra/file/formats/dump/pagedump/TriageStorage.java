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
package ghidra.file.formats.dump.pagedump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;

public class TriageStorage implements StructConverter {

	public final static String NAME = "_MI_TRIAGE_STORAGE";

	private int version;
	private int size;
	private int mmSpecialPoolTag;
	private int miTriageActionTaken;

	private int mmVerifyDriverLevel;
	private int kernelVerifier;
	private long mmMaximumNonPagedPool;
	private long mmAllocatedNonPagedPool;

	private long pagedPoolMaximum;
	private long pagePoolAllocated;

	private long commitedPages;
	private long commitedPagesPeak;
	private long commitedPagesMaximum;

	private DumpFileReader reader;
	private long index;
	private int psz;

	TriageStorage(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setVersion(reader.readNextInt());
		setSize(reader.readNextInt());
		setMmSpecialPoolTag(reader.readNextInt());
		setMiTriageActionTaken(reader.readNextInt());
		setMmVerifyDriverLevel(reader.readNextInt());
		setKernelVerifier(reader.readNextInt());
		setMmMaximumNonPagedPool(reader.readNextLong());
		setMmAllocatedNonPagedPool(reader.readNextLong());
		setPagedPoolMaximum(reader.readNextLong());
		setPagePoolAllocated(reader.readNextLong());
		setCommitedPages(reader.readNextLong());
		setCommitedPagesPeak(reader.readNextLong());
		setCommitedPagesMaximum(reader.readNextLong());

	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "Version", null);
		struct.add(DWORD, 4, "Size", null);
		struct.add(DWORD, 4, "MmSpecialPoolTag", null);
		struct.add(DWORD, 4, "MiTriageActionTaken", null);
		struct.add(DWORD, 4, "MmVerifyDriverLevel", null);
		struct.add(DWORD, 4, "KernelVerifier", null);
		struct.add(QWORD, psz, "MmMaximumNonPagedPool", null);
		struct.add(QWORD, psz, "MmAllocatedNonPagedPool", null);
		struct.add(QWORD, psz, "PagedPoolMaximum", null);
		struct.add(QWORD, psz, "PagePoolAllocated", null);
		struct.add(QWORD, psz, "CommitedPages", null);
		struct.add(QWORD, psz, "CommitedPagesPeak", null);
		struct.add(QWORD, psz, "CommitedPagesMaximum", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getVersion() {
		return version;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public int getMmSpecialPoolTag() {
		return mmSpecialPoolTag;
	}

	public void setMmSpecialPoolTag(int mmSpecialPoolTag) {
		this.mmSpecialPoolTag = mmSpecialPoolTag;
	}

	public int getMiTriageActionTaken() {
		return miTriageActionTaken;
	}

	public void setMiTriageActionTaken(int miTriageActionTaken) {
		this.miTriageActionTaken = miTriageActionTaken;
	}

	public int getMmVerifyDriverLevel() {
		return mmVerifyDriverLevel;
	}

	public void setMmVerifyDriverLevel(int mmVerifyDriverLevel) {
		this.mmVerifyDriverLevel = mmVerifyDriverLevel;
	}

	public long getMmMaximumNonPagedPool() {
		return mmMaximumNonPagedPool;
	}

	public void setMmMaximumNonPagedPool(long mmMaximumNonPagedPool) {
		this.mmMaximumNonPagedPool = mmMaximumNonPagedPool;
	}

	public int getKernelVerifier() {
		return kernelVerifier;
	}

	public void setKernelVerifier(int kernelVerifier) {
		this.kernelVerifier = kernelVerifier;
	}

	public long getMmAllocatedNonPagedPool() {
		return mmAllocatedNonPagedPool;
	}

	public void setMmAllocatedNonPagedPool(long mmAllocatedNonPagedPool) {
		this.mmAllocatedNonPagedPool = mmAllocatedNonPagedPool;
	}

	public long getPagedPoolMaximum() {
		return pagedPoolMaximum;
	}

	public void setPagedPoolMaximum(long pagedPoolMaximum) {
		this.pagedPoolMaximum = pagedPoolMaximum;
	}

	public long getPagePoolAllocated() {
		return pagePoolAllocated;
	}

	public void setPagePoolAllocated(long pagePoolAllocated) {
		this.pagePoolAllocated = pagePoolAllocated;
	}

	public long getCommitedPages() {
		return commitedPages;
	}

	public void setCommitedPages(long commitedPages) {
		this.commitedPages = commitedPages;
	}

	public long getCommitedPagesPeak() {
		return commitedPagesPeak;
	}

	public void setCommitedPagesPeak(long commitedPagesPeak) {
		this.commitedPagesPeak = commitedPagesPeak;
	}

	public long getCommitedPagesMaximum() {
		return commitedPagesMaximum;
	}

	public void setCommitedPagesMaximum(long commitedPagesMaximum) {
		this.commitedPagesMaximum = commitedPagesMaximum;
	}

}
