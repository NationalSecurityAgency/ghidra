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
package ghidra.app.util.bin.format.pe.dvrt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_FUNCTION_OVERRIDE_HEADER} structure
 */
public class ImageFunctionOverrideHeader extends AbstractImageDynamicRelocationHeader {

	private int funcOverrideSize;

	private List<ImageFunctionOverrideDynamicRelocation> funcOverrideInfos = new ArrayList<>();
	private List<ImageBddInfo> bddInfos = new ArrayList<>();

	/**
	 * Creates a new {@link ImageFunctionOverrideHeader}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param rva The relative virtual address of the structure
	 * @param dvrtEntrySize The size in bytes of this header's 
	 *   {@link ImageDynamicRelocation DVRT entry}
	 * @throws IOException if there was an IO-related error
	 */
	public ImageFunctionOverrideHeader(BinaryReader reader, long rva, int dvrtEntrySize)
			throws IOException {
		super(rva);
		long origIndex = reader.getPointerIndex();

		funcOverrideSize = reader.readNextInt();

		long startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + funcOverrideSize; i = reader.getPointerIndex()) {
			funcOverrideInfos
					.add(new ImageFunctionOverrideDynamicRelocation(reader, rva + (i - origIndex)));
		}

		int bddSize = dvrtEntrySize - 4 - funcOverrideSize;
		startIndex = reader.getPointerIndex();
		for (long i = startIndex; i < startIndex + bddSize; i = reader.getPointerIndex()) {
			bddInfos.add(new ImageBddInfo(reader, rva + (i - origIndex)));
		}
	}

	/**
	 * {@return the function override size}
	 */
	public int getFuncOverrideSize() {
		return funcOverrideSize;
	}

	/**
	 * {@return the {@link List} of {@link ImageFunctionOverrideDynamicRelocation}s}
	 */
	public List<ImageFunctionOverrideDynamicRelocation> getFuncOverrideInfo() {
		return funcOverrideInfos;
	}

	/**
	 * {@return the {@link List} of {@link ImageBddInfo}s}
	 */
	public List<ImageBddInfo> getBddInfo() {
		return bddInfos;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		Address imageBase = program.getImageBase();
		DataType dt = toDataType();
		PeUtils.createData(program, imageBase.add(rva), dt, log);
		for (ImageFunctionOverrideDynamicRelocation info : funcOverrideInfos) {
			info.markup(program, isBinary, monitor, log, ntHeader);
		}
		for (ImageBddInfo info : bddInfos) {
			info.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_FUNCTION_OVERRIDE_HEADER", 0);
		struct.add(DWORD, "FuncOverrideSize", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
