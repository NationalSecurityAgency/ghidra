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

public class MiscInfoStream implements StructConverter {

	public final static String NAME = "MINIDUMP_MISC_INFO";

	private int sizeOfInfo;
	private int flags1;
	private int processId;
	private int processCreateTime;
	private int processUserTime;
	private int processKernelTime;

	private int processorMaxMhz;
	private int processorCurrentMhz;
	private int processorMhzLimit;
	private int processorMaxIdleState;
	private int processorCurrentIdleState;

	private int processIntegrityLevel;
	private int processExecuteFlags;
	private int protectedProcess;
	private int timeZoneId;

	private int bias;
	private String standardName; //[32]
	//SYSTEMTIME standardDate;
	private int standardBias;
	private String daylightName; //[32]
	//SYSTEMTIME daylightDate;
	private int daylightBias;

	/*
	  WORD wYear;
	  WORD wMonth;
	  WORD wDayOfWeek;
	  WORD wDay;
	  WORD wHour;
	  WORD wMinute;
	  WORD wSecond;
	  WORD wMilliseconds;
	*/

	private String buildString;
	private String dbgBuildStr;

	private DumpFileReader reader;
	private long index;
	private boolean format2, format3, format4;

	MiscInfoStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSizeOfInfo(reader.readNextInt());
		setFlags1(reader.readNextInt());
		setProcessId(reader.readNextInt());
		setProcessCreateTime(reader.readNextInt());
		setProcessUserTime(reader.readNextInt());
		setProcessKernelTime(reader.readNextInt());
		format2 = sizeOfInfo > reader.getPointerIndex() - index;
		if (format2) {
			setProcessorMaxMhz(reader.readNextInt());
			setProcessorCurrentMhz(reader.readNextInt());
			setProcessorMhzLimit(reader.readNextInt());
			setProcessorMaxIdleState(reader.readNextInt());
			setProcessorCurrentIdleState(reader.readNextInt());
		}
		format3 = sizeOfInfo > reader.getPointerIndex() - index;
		if (format3) {
			setProcessIntegrityLevel(reader.readNextInt());
			setProcessExecuteFlags(reader.readNextInt());
			setProcessorMhzLimit(reader.readNextInt());
			setProtectedProcess(reader.readNextInt());
			setTimeZoneId(reader.readNextInt());

			setBias(reader.readNextInt());
			setStandardName(reader.readNextUnicodeString());
			reader.readNextLong();
			reader.readNextLong();
			setStandardBias(reader.readNextInt());
			setDaylightName(reader.readNextUnicodeString());
			reader.readNextLong();
			reader.readNextLong();
			setTimeZoneId(reader.readNextInt());
			setDaylightBias(reader.readNextInt());
		}
		format4 = sizeOfInfo > reader.getPointerIndex() - index;
		if (format4) {
			setProtectedProcess(reader.readNextInt());
			setTimeZoneId(reader.readNextInt());
		}

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "SizeOfInfo", null);
		struct.add(DWORD, 4, "Flags1", null);
		struct.add(DWORD, 4, "ProcessId", null);
		struct.add(DWORD, 4, "ProcessCreateTime", null);
		struct.add(DWORD, 4, "ProcessUserTime", null);
		struct.add(DWORD, 4, "ProcessKernelTime", null);
		if (format2) {
			struct.add(DWORD, 4, "ProcessorMaxMhz", null);
			struct.add(DWORD, 4, "ProcessorCurrentMhz", null);
			struct.add(DWORD, 4, "ProcessorMhzLimit", null);
			struct.add(DWORD, 4, "ProcessorMaxIdleState", null);
			struct.add(DWORD, 4, "ProcessorCurrentIdleState", null);
		}
		if (format3) {
			struct.add(DWORD, 4, "ProcessIntegrityLevel", null);
			struct.add(DWORD, 4, "ProcessExecuteFlags", null);
			struct.add(DWORD, 4, "ProtectedProcess", null);
			struct.add(DWORD, 4, "TimeZoneId", null);

			StructureDataType s00 = new StructureDataType("SYSTEM_TIME", 0);
			s00.add(WORD, 2, "Year", null);
			s00.add(WORD, 2, "Month", null);
			s00.add(WORD, 2, "DayOfWeek", null);
			s00.add(WORD, 2, "Day", null);
			s00.add(WORD, 2, "Hour", null);
			s00.add(WORD, 2, "Minute", null);
			s00.add(WORD, 2, "Second", null);
			s00.add(WORD, 2, "Milliseconds", null);

			StructureDataType s0 = new StructureDataType("TIME_ZONE_INFORMATION", 0);
			s0.add(DWORD, 4, "Bias", null);
			s0.add(UTF16, 64, "StandardName", null);
			s0.add(s00, s00.getLength(), "StandardDate", null);
			s0.add(DWORD, 4, "StandardBias", null);
			s0.add(UTF16, 64, "DaylightName", null);
			s0.add(s00, s00.getLength(), "DaylightDate", null);
			s0.add(DWORD, 4, "DaylightBias", null);

			struct.add(s0, s0.getLength(), "TimeZone", null);
		}
		if (format4) {
			struct.add(UTF16, 256, "BuildString", null);
			struct.add(UTF16, 40, "DbgBldStr", null);
		}

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getSizeOfInfo() {
		return sizeOfInfo;
	}

	public void setSizeOfInfo(int sizeOfInfo) {
		this.sizeOfInfo = sizeOfInfo;
	}

	public int getFlags1() {
		return flags1;
	}

	public void setFlags1(int flags1) {
		this.flags1 = flags1;
	}

	public int getProcessId() {
		return processId;
	}

	public void setProcessId(int processId) {
		this.processId = processId;
	}

	public int getProcessCreateTime() {
		return processCreateTime;
	}

	public void setProcessCreateTime(int processCreateTime) {
		this.processCreateTime = processCreateTime;
	}

	public int getProcessUserTime() {
		return processUserTime;
	}

	public void setProcessUserTime(int processUserTime) {
		this.processUserTime = processUserTime;
	}

	public int getProcessKernelTime() {
		return processKernelTime;
	}

	public void setProcessKernelTime(int processKernelTime) {
		this.processKernelTime = processKernelTime;
	}

	public int getProcessorMaxMhz() {
		return processorMaxMhz;
	}

	public void setProcessorMaxMhz(int processorMaxMhz) {
		this.processorMaxMhz = processorMaxMhz;
	}

	public int getProcessorCurrentMhz() {
		return processorCurrentMhz;
	}

	public void setProcessorCurrentMhz(int processorCurrentMhz) {
		this.processorCurrentMhz = processorCurrentMhz;
	}

	public int getProcessorMhzLimit() {
		return processorMhzLimit;
	}

	public void setProcessorMhzLimit(int processorMhzLimit) {
		this.processorMhzLimit = processorMhzLimit;
	}

	public int getProcessorMaxIdleState() {
		return processorMaxIdleState;
	}

	public void setProcessorMaxIdleState(int processorMaxIdleState) {
		this.processorMaxIdleState = processorMaxIdleState;
	}

	public int getProcessorCurrentIdleState() {
		return processorCurrentIdleState;
	}

	public void setProcessorCurrentIdleState(int processorCurrentIdleState) {
		this.processorCurrentIdleState = processorCurrentIdleState;
	}

	public int getProcessIntegrityLevel() {
		return processIntegrityLevel;
	}

	public void setProcessIntegrityLevel(int processIntegrityLevel) {
		this.processIntegrityLevel = processIntegrityLevel;
	}

	public int getProcessExecuteFlags() {
		return processExecuteFlags;
	}

	public void setProcessExecuteFlags(int processExecuteFlags) {
		this.processExecuteFlags = processExecuteFlags;
	}

	public int getProtectedProcess() {
		return protectedProcess;
	}

	public void setProtectedProcess(int protectedProcess) {
		this.protectedProcess = protectedProcess;
	}

	public int getTimeZoneId() {
		return timeZoneId;
	}

	public void setTimeZoneId(int timeZoneId) {
		this.timeZoneId = timeZoneId;
	}

	public int getBias() {
		return bias;
	}

	public void setBias(int bias) {
		this.bias = bias;
	}

	public String getStandardName() {
		return standardName;
	}

	public void setStandardName(String standardName) {
		this.standardName = standardName;
	}

	public int getStandardBias() {
		return standardBias;
	}

	public void setStandardBias(int standardBias) {
		this.standardBias = standardBias;
	}

	public String getDaylightName() {
		return daylightName;
	}

	public void setDaylightName(String daylightName) {
		this.daylightName = daylightName;
	}

	public int getDaylightBias() {
		return daylightBias;
	}

	public void setDaylightBias(int daylightBias) {
		this.daylightBias = daylightBias;
	}

	public String getBuildString() {
		return buildString;
	}

	public void setBuildString(String buildString) {
		this.buildString = buildString;
	}

	public String getDbgBuildStr() {
		return dbgBuildStr;
	}

	public void setDbgBuildStr(String dbgBuildStr) {
		this.dbgBuildStr = dbgBuildStr;
	}
}
