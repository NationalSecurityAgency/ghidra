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
package ghidra.app.util.bin.format.pe.chpe;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a {@code IMAGE_ARM64EC_METADATA} structure
 */
@SuppressWarnings("unused")
public class ImageArm64ecMetadata implements StructConverter, PeMarkupable {

	private int version;
	private int codeMap;
	private int codeMapCount;
	private int codeRangesToEntryPoints;
	private int redirectionMetadata;
	private int osArm64xDispatchCallNoRedirect;
	private int osArm64xDispatchRet;
	private int osArm64xDispatchCall;
	private int osArm64xDispatchIcall;
	private int osArm64xDispatchIcallCfg;
	private int alternateEntryPoint;
	private int auxiliaryIat;
	private int codeRangesToEntryPointsCount;
	private int redirectionMetadataCount;
	private int getX64InformationFunctionPointer;
	private int setX64InformationFunctionPointer;
	private int extraRfeTable;
	private int extraRfeTableSize;
	private int osArm64xDispatchFptr;
	private int auxiliaryIatCopy;
	private int osArm64xHelper0;
	private int osArm64xHelper1;
	private int osArm64xHelper2;
	private int osArm64xHelper3;
	private int osArm64xHelper4;
	private int osArm64xHelper5;
	private int osArm64xHelper6;
	private int osArm64xHelper7;
	private int osArm64xHelper8;

	private long va;
	private List<ImageChpeRangeEntry> codeMapEntries = new ArrayList<>();
	private List<ImageArm64ecRedirectionEntry> redirectionEntries = new ArrayList<>();
	private List<ImageArm64ecCodeRangeEntryPoint> codeRangeEntryPoints = new ArrayList<>();

	/**
	 * Creates a new {@link ImageArm64ecMetadata}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the structure
	 * @param nt The {@link NTHeader}
	 * @param va The virtual address of the structure
	 * @throws IOException if there was an IO-related error
	 */
	public ImageArm64ecMetadata(BinaryReader reader, NTHeader nt, long va) throws IOException {
		this.va = va;
		
		version = reader.readNextInt();
		codeMap = reader.readNextInt();
		codeMapCount = reader.readNextInt();
		codeRangesToEntryPoints = reader.readNextInt();
		redirectionMetadata = reader.readNextInt();
		osArm64xDispatchCallNoRedirect = reader.readNextInt();
		osArm64xDispatchRet = reader.readNextInt();
		osArm64xDispatchCall = reader.readNextInt();
		osArm64xDispatchIcall = reader.readNextInt();
		osArm64xDispatchIcallCfg = reader.readNextInt();
		alternateEntryPoint = reader.readNextInt();
		auxiliaryIat = reader.readNextInt();
		codeRangesToEntryPointsCount = reader.readNextInt();
		redirectionMetadataCount = reader.readNextInt();
		getX64InformationFunctionPointer = reader.readNextInt();
		setX64InformationFunctionPointer = reader.readNextInt();
		extraRfeTable = reader.readNextInt();
		extraRfeTableSize = reader.readNextInt();
		osArm64xDispatchFptr = reader.readNextInt();
		auxiliaryIatCopy = reader.readNextInt();
		if (version >= 2) {
			osArm64xHelper0 = reader.readNextInt();
			osArm64xHelper1 = reader.readNextInt();
			osArm64xHelper2 = reader.readNextInt();
			osArm64xHelper3 = reader.readNextInt();
			osArm64xHelper4 = reader.readNextInt();
			osArm64xHelper5 = reader.readNextInt();
			osArm64xHelper6 = reader.readNextInt();
			osArm64xHelper7 = reader.readNextInt();
			osArm64xHelper8 = reader.readNextInt();
		}
		
		BinaryReader r = reader.clone(nt.rvaToPointer(codeMap));
		long startIndex = r.getPointerIndex();
		for (int i = 0; i < codeMapCount; i++) {
			codeMapEntries.add(new ImageChpeRangeEntry(r,
				codeMap + (r.getPointerIndex() - startIndex)));
		}

		r = reader.clone(nt.rvaToPointer(codeRangesToEntryPoints));
		startIndex = r.getPointerIndex();
		for (int i = 0; i < codeRangesToEntryPointsCount; i++) {
			codeRangeEntryPoints.add(new ImageArm64ecCodeRangeEntryPoint(r,
				codeRangesToEntryPoints + (r.getPointerIndex() - startIndex)));
		}

		r = reader.clone(nt.rvaToPointer(redirectionMetadata));
		startIndex = r.getPointerIndex();
		for (int i = 0; i < redirectionMetadataCount; i++) {
			redirectionEntries.add(new ImageArm64ecRedirectionEntry(r,
				redirectionMetadata + (r.getPointerIndex() - startIndex)));
		}
	}

	/**
	 * {@return the metadata version}
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * {@return the {@link List} of {@link ImageChpeRangeEntry code map entries}}
	 */
	public List<ImageChpeRangeEntry> getCodeMapEntries() {
		return codeMapEntries;
	}

	/**
	 * {@return the {@link List} of {@link ImageArm64ecRedirectionEntry redirection entries}}
	 */
	public List<ImageArm64ecRedirectionEntry> getRedirectionEntries() {
		return redirectionEntries;
	}

	/**
	 * {@return the {@link List} of {@link ImageArm64ecCodeRangeEntryPoint code range entry points}}
	 */
	public List<ImageArm64ecCodeRangeEntryPoint> getCodeRangeEntryPoints() {
		return codeRangeEntryPoints;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		PeUtils.createData(program, space.getAddress(va), toDataType(), log);
		for (ImageChpeRangeEntry entry : codeMapEntries) {
			entry.markup(program, isBinary, monitor, log, ntHeader);
		}
		for (ImageArm64ecCodeRangeEntryPoint entry : codeRangeEntryPoints) {
			entry.markup(program, isBinary, monitor, log, ntHeader);
		}
		for (ImageArm64ecRedirectionEntry entry : redirectionEntries) {
			entry.markup(program, isBinary, monitor, log, ntHeader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("IMAGE_ARM64EC_METADATA", 0);
		struct.add(DWORD, "Version", null);
		struct.add(IBO32, "CodeMap", null);
		struct.add(DWORD, "CodeMapCount", null);
		struct.add(IBO32, "CodeRangesToEntryPoint", null);
		struct.add(IBO32, "RedirectionMetdata", null);
		struct.add(IBO32, "__os_arm64x_dispatch_call_no_redirect", null);
		struct.add(IBO32, "__os_arm64x_dispatch_ret", null);
		struct.add(IBO32, "__os_arm64x_dispatch_call", null);
		struct.add(IBO32, "__os_arm64x_dispatch_icall", null);
		struct.add(IBO32, "__os_arm64x_dispatch_icall_cfg", null);
		struct.add(IBO32, "AlternateEntryPoint", null);
		struct.add(IBO32, "AuxiliaryIAT", null);
		struct.add(DWORD, "CodeRangesToEntryPointsCount", null);
		struct.add(DWORD, "RedirectionMetadataCount", null);
		struct.add(IBO32, "GetX64InformationFunctionPointer", null);
		struct.add(IBO32, "SetX64InformationFunctionPointer", null);
		struct.add(IBO32, "ExtraRFETable", null);
		struct.add(DWORD, "ExtraRFETableSize", null);
		struct.add(IBO32, "__os_arm64x_dispatch_fptr", null);
		struct.add(IBO32, "AuxiliaryIATCopy", null);
		if (version >= 2) {
			struct.add(IBO32, "__os_arm64x_helper0", null);
			struct.add(IBO32, "__os_arm64x_helper1", null);
			struct.add(IBO32, "__os_arm64x_helper2", null);
			struct.add(IBO32, "__os_arm64x_helper3", null);
			struct.add(IBO32, "__os_arm64x_helper4", null);
			struct.add(IBO32, "__os_arm64x_helper5", null);
			struct.add(IBO32, "__os_arm64x_helper6", null);
			struct.add(IBO32, "__os_arm64x_helper7", null);
			struct.add(IBO32, "__os_arm64x_helper8", null);
		}

		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

}
