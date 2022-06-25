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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ProcessVmCountersStream implements StructConverter {

	public final static String NAME = "MINIDUMP_PROCESS_VM_COUNTERS";

	private short revision;
	private short flags;
	private int pageFaultCount;
	private long peakWorkingSetSize;
	private long workingSetSize;
	private long quotaPeakPagedPoolUsage;
	private long quotaPagedPoolUsage;
	private long quotaPeakNonPagedPoolUsage;
	private long quotaNonPagedPoolUsage;
	private long pagefileUsage;
	private long peakPagefileUsage;
	private long peakVirtualSize;            // VIRTUALSIZE
	private long virtualSize;                // VIRTUALSIZE
	private long privateUsage;               // EX+
	private long privateWorkingSetSize;      // EX2+
	private long sharedCommitUsage;          // EX2+
	private long jobSharedCommitUsage;       // JOB+
	private long jobPrivateCommitUsage;      // JOB+
	private long jobPeakPrivateCommitUsage;  // JOB+
	private long jobPrivateCommitLimit;      // JOB+
	private long jobTotalCommitLimit;        // JOB+

	private DumpFileReader reader;
	private long index;
	private boolean expandedFormat;

	ProcessVmCountersStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setRevision(reader.readNextShort());
		expandedFormat = getRevision() > 1;
		if (expandedFormat) {
			setFlags(reader.readNextShort());
		}
		setPageFaultCount(reader.readNextInt());
		setPeakWorkingSetSize(reader.readNextLong());
		setWorkingSetSize(reader.readNextLong());
		setQuotaPeakPagedPoolUsage(reader.readNextLong());
		setQuotaPagedPoolUsage(reader.readNextLong());
		setQuotaPeakNonPagedPoolUsage(reader.readNextLong());
		setQuotaNonPagedPoolUsage(reader.readNextLong());
		setPagefileUsage(reader.readNextLong());
		setPeakPagefileUsage(reader.readNextLong());
		if (expandedFormat) {
			setPeakVirtualSize(reader.readNextLong());
			setVirtualSize(reader.readNextLong());
		}
		setPrivateUsage(reader.readNextLong());
		if (expandedFormat) {
			setPrivateWorkingSetSize(reader.readNextLong());
			setSharedCommitUsage(reader.readNextLong());
			setJobSharedCommitUsage(reader.readNextLong());
			setJobPrivateCommitUsage(reader.readNextLong());
			setJobPeakPrivateCommitUsage(reader.readNextLong());
			setJobPrivateCommitLimit(reader.readNextLong());
			setJobTotalCommitLimit(reader.readNextLong());
		}

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(WORD, 2, "Revision", null);
		if (expandedFormat) {
			struct.add(WORD, 2, "Flags", null);
		}
		struct.add(DWORD, 4, "PageFaultCount", null);
		struct.add(QWORD, 8, "PeakWorkingSetSize", null);
		struct.add(QWORD, 8, "WorkingSetSize", null);
		struct.add(QWORD, 8, "QuotaPeakPagedPoolUsage", null);
		struct.add(QWORD, 8, "QuotaPagedPoolUsage", null);
		struct.add(QWORD, 8, "QuotaPeakNonPagedPoolUsage", null);
		struct.add(QWORD, 8, "QuotaNonPagedPoolUsage", null);
		struct.add(QWORD, 8, "PagefileUsage", null);
		struct.add(QWORD, 8, "PeakPagefileUsage", null);
		if (expandedFormat) {
			struct.add(QWORD, 8, "PeakVirtualSize", null);
			struct.add(QWORD, 8, "VirtualSize", null);
		}
		struct.add(QWORD, 8, "PrivateUsage", null);
		if (expandedFormat) {
			struct.add(QWORD, 8, "PrivateWorkingSetSize", null);
			struct.add(QWORD, 8, "SharedCommitUsage", null);
			struct.add(QWORD, 8, "JobSharedCommitUsage", null);
			struct.add(QWORD, 8, "JobPrivateCommitUsage", null);
			struct.add(QWORD, 8, "JobPeakPrivateCommitUsage", null);
			struct.add(QWORD, 8, "JobPrivateCommitLimit", null);
			struct.add(QWORD, 8, "JobTotalCommitLimit", null);
		}

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public short getRevision() {
		return revision;
	}

	public void setRevision(short revision) {
		this.revision = revision;
	}

	public short getFlags() {
		return flags;
	}

	public void setFlags(short flags) {
		this.flags = flags;
	}

	public int getPageFaultCount() {
		return pageFaultCount;
	}

	public void setPageFaultCount(int pageFaultCount) {
		this.pageFaultCount = pageFaultCount;
	}

	public long getPeakWorkingSetSize() {
		return peakWorkingSetSize;
	}

	public void setPeakWorkingSetSize(long peakWorkingSetSize) {
		this.peakWorkingSetSize = peakWorkingSetSize;
	}

	public long getWorkingSetSize() {
		return workingSetSize;
	}

	public void setWorkingSetSize(long workingSetSize) {
		this.workingSetSize = workingSetSize;
	}

	public long getQuotaPeakPagedPoolUsage() {
		return quotaPeakPagedPoolUsage;
	}

	public void setQuotaPeakPagedPoolUsage(long quotaPeakPagedPoolUsage) {
		this.quotaPeakPagedPoolUsage = quotaPeakPagedPoolUsage;
	}

	public long getQuotaPagedPoolUsage() {
		return quotaPagedPoolUsage;
	}

	public void setQuotaPagedPoolUsage(long quotaPagedPoolUsage) {
		this.quotaPagedPoolUsage = quotaPagedPoolUsage;
	}

	public long getQuotaPeakNonPagedPoolUsage() {
		return quotaPeakNonPagedPoolUsage;
	}

	public void setQuotaPeakNonPagedPoolUsage(long quotaPeakNonPagedPoolUsage) {
		this.quotaPeakNonPagedPoolUsage = quotaPeakNonPagedPoolUsage;
	}

	public long getQuotaNonPagedPoolUsage() {
		return quotaNonPagedPoolUsage;
	}

	public void setQuotaNonPagedPoolUsage(long quotaNonPagedPoolUsage) {
		this.quotaNonPagedPoolUsage = quotaNonPagedPoolUsage;
	}

	public long getPagefileUsage() {
		return pagefileUsage;
	}

	public void setPagefileUsage(long pagefileUsage) {
		this.pagefileUsage = pagefileUsage;
	}

	public long getPeakPagefileUsage() {
		return peakPagefileUsage;
	}

	public void setPeakPagefileUsage(long peakPagefileUsage) {
		this.peakPagefileUsage = peakPagefileUsage;
	}

	public long getPeakVirtualSize() {
		return peakVirtualSize;
	}

	public void setPeakVirtualSize(long peakVirtualSize) {
		this.peakVirtualSize = peakVirtualSize;
	}

	public long getVirtualSize() {
		return virtualSize;
	}

	public void setVirtualSize(long virtualSize) {
		this.virtualSize = virtualSize;
	}

	public long getPrivateUsage() {
		return privateUsage;
	}

	public void setPrivateUsage(long privateUsage) {
		this.privateUsage = privateUsage;
	}

	public long getPrivateWorkingSetSize() {
		return privateWorkingSetSize;
	}

	public void setPrivateWorkingSetSize(long privateWorkingSetSize) {
		this.privateWorkingSetSize = privateWorkingSetSize;
	}

	public long getSharedCommitUsage() {
		return sharedCommitUsage;
	}

	public void setSharedCommitUsage(long sharedCommitUsage) {
		this.sharedCommitUsage = sharedCommitUsage;
	}

	public long getJobSharedCommitUsage() {
		return jobSharedCommitUsage;
	}

	public void setJobSharedCommitUsage(long jobSharedCommitUsage) {
		this.jobSharedCommitUsage = jobSharedCommitUsage;
	}

	public long getJobPrivateCommitUsage() {
		return jobPrivateCommitUsage;
	}

	public void setJobPrivateCommitUsage(long jobPrivateCommitUsage) {
		this.jobPrivateCommitUsage = jobPrivateCommitUsage;
	}

	public long getJobPeakPrivateCommitUsage() {
		return jobPeakPrivateCommitUsage;
	}

	public void setJobPeakPrivateCommitUsage(long jobPeakPrivateCommitUsage) {
		this.jobPeakPrivateCommitUsage = jobPeakPrivateCommitUsage;
	}

	public long getJobPrivateCommitLimit() {
		return jobPrivateCommitLimit;
	}

	public void setJobPrivateCommitLimit(long jobPrivateCommitLimit) {
		this.jobPrivateCommitLimit = jobPrivateCommitLimit;
	}

	public long getJobTotalCommitLimit() {
		return jobTotalCommitLimit;
	}

	public void setJobTotalCommitLimit(long jobTotalCommitLimit) {
		this.jobTotalCommitLimit = jobTotalCommitLimit;
	}

}
