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
package ghidra.app.util.bin.format.golang;

import static ghidra.app.util.bin.StructConverter.ASCII;
import static ghidra.app.util.bin.StructConverter.BYTE;

import java.util.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * A program section that contains Go build information strings, namely go module package names,
 * go module dependencies, and build/compiler flags, as well as the golang version itself.
 */
public class GoBuildInfo implements ElfInfoItem {

	public static final String SECTION_NAME = ".go.buildinfo";

	// Defined in golang src/debug/buildinfo/buildinfo.go
	// NOTE: ISO_8859_1 charset is required to not mangle the \u00ff when converting to bytes
	private static final byte[] GO_BUILDINF_MAGIC =
		"\u00ff Go buildinf:".getBytes(StandardCharsets.ISO_8859_1);

	// Defined in golang src/cmd/go/internal/modload/build.go
	private static final byte[] INFOSTART_SENTINEL =
		NumericUtilities.convertStringToBytes("3077af0c9274080241e1c107e6d618e6");
	private static final byte[] INFOEND_SENTINEL =
		NumericUtilities.convertStringToBytes("f932433186182072008242104116d8f2");

	private static final int FLAG_ENDIAN = (1 << 0);
	private static final int FLAG_INLINE_STRING = (1 << 1);

	/**
	 * Reads a GoBuildInfo ".go.buildinfo" section from the specified Program, if present.
	 * 
	 * @param program {@link Program} that contains the ".go.buildinfo" section
	 * @return new {@link GoBuildInfo} section, if present, null if missing or error
	 */
	public static GoBuildInfo fromProgram(Program program) {
		ItemWithAddress<GoBuildInfo> wrappedItem = findBuildInfo(program);
		return wrappedItem != null ? wrappedItem.item() : null;
	}

	public static ItemWithAddress<GoBuildInfo> findBuildInfo(Program program) {
		// try as if binary is ELF
		ItemWithAddress<GoBuildInfo> wrappedItem =
			ElfInfoItem.readItemFromSection(program, SECTION_NAME, GoBuildInfo::read);
		if (wrappedItem == null) {
			// if not present, try common PE location for buildinfo, using "ElfInfoItem" logic
			// even though this might be a PE binary, cause it doesn't matter
			wrappedItem = ElfInfoItem.readItemFromSection(program, ".data", GoBuildInfo::read);
		}
		return wrappedItem;
	}

	/**
	 * Reads a GoBuildInfo ".go.buildinfo" section from the specified stream.
	 * 
	 * @param reader BinaryReader that contains the ".go.buildinfo" section
	 * @param program Program that contains the ".go.buildinfo" section
	 * @return new {@link GoBuildInfo} instance, never null
	 * @throws IOException if error reading or bad data
	 */
	public static GoBuildInfo read(BinaryReader reader, Program program) throws IOException {
		byte[] magicBytes = reader.readNextByteArray(GO_BUILDINF_MAGIC.length /* 14 */);
		if (!Arrays.equals(magicBytes, GO_BUILDINF_MAGIC)) {
			throw new IOException("Missing GoBuildInfo magic");
		}
		int pointerSize = reader.readNextUnsignedByte();
		int flags = reader.readNextUnsignedByte();
		Endian endian = (flags & FLAG_ENDIAN) == 0 ? Endian.LITTLE : Endian.BIG;
		boolean inlineStr = (flags & FLAG_INLINE_STRING) != 0;

		if (reader.isBigEndian() && endian != Endian.BIG) {
			throw new IOException("Mixed endian-ness");
		}

		return readStringInfo(reader, inlineStr, program, pointerSize);
	}

	/**
	 * Probes the specified InputStream and returns true if it starts with a go buildinfo magic
	 * signature.
	 * 
	 * @param is InputStream
	 * @return true if starts with buildinfo magic signature
	 */
	public static boolean isPresent(InputStream is) {
		try {
			byte[] buffer = new byte[GO_BUILDINF_MAGIC.length];
			int bytesRead = is.read(buffer);
			return bytesRead == GO_BUILDINF_MAGIC.length &&
				Arrays.equals(buffer, GO_BUILDINF_MAGIC);
		}
		catch (IOException e) {
			// fall thru
		}
		return false;
	}

	private final int pointerSize;
	private final Endian endian;
	private final String version;	// golang compiler version 
	private final String path;
	private final GoModuleInfo moduleInfo;	// info about the module that contains the main package.  version typically will be "(devel)" 
	private final List<GoModuleInfo> dependencies;
	private final List<GoBuildSettings> buildSettings; // compile/linker flags used during build process

	public GoBuildInfo(int pointerSize, Endian endian, String version, String path,
			GoModuleInfo moduleInfo, List<GoModuleInfo> dependencies,
			List<GoBuildSettings> buildSettings) {
		this.pointerSize = pointerSize;
		this.endian = endian;
		this.version = version;
		this.path = path;
		this.moduleInfo = moduleInfo;
		this.dependencies = dependencies;
		this.buildSettings = buildSettings;
	}

	public int getPointerSize() {
		return pointerSize;
	}

	public Endian getEndian() {
		return endian;
	}

	public String getVersion() {
		return version;
	}

	public GoVer getVerEnum() {
		return GoVer.parse(version);
	}

	public String getPath() {
		return path;
	}

	public GoModuleInfo getModuleInfo() {
		return moduleInfo;
	}

	public List<GoModuleInfo> getDependencies() {
		return dependencies;
	}

	public List<GoBuildSettings> getBuildSettings() {
		return buildSettings;
	}

	@Override
	public void markupProgram(Program program, Address address) {
		decorateProgramInfo(program.getOptions(Program.PROGRAM_INFO));

		try {
			StructureDataType struct = toStructure(program.getDataTypeManager());
			if (struct != null) {
				DataUtilities.createData(program, address, struct, -1, false,
					ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
			}
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Failed to markup GoBuildInfo at %s: %s".formatted(address, this));
		}
	}

	public void decorateProgramInfo(Options props) {
		GoVer.setProgramPropertiesWithOriginalVersionString(props, getVersion());
		props.setString("Golang app path", getPath());
		if (getModuleInfo() != null) {
			getModuleInfo()
					.asKeyValuePairs("Golang main package ")
					.entrySet()
					.stream()
					.forEach(entry -> props.setString(entry.getKey(), entry.getValue()));
		}
		int depNum = 0;
		for (GoModuleInfo dep : getDependencies()) {
			String key = "Golang dep[%4d]".formatted(depNum++);
			props.setString(key, dep.getFormattedString());
		}
		for (GoBuildSettings buildSetting : getBuildSettings()) {
			props.setString("Golang build[" + buildSetting.key().replaceAll("\\.", "_") + "]",
				buildSetting.value());
		}
	}

	StructureDataType toStructure(DataTypeManager dtm) {
		StructureDataType result =
			new StructureDataType(GoConstants.GOLANG_CATEGORYPATH, "GoBuildInfo", 0, dtm);
		result.add(new ArrayDataType(ASCII, 14, -1, dtm), "magic", "\\xff Go buildinf:");
		result.add(BYTE, "ptrSize", null);
		result.add(BYTE, "flags", null);

		return result;
	}

	@Override
	public String toString() {
		return String.format("GoBuildInfo [pointerSize=%s, endian=%s, version=%s, path=%s]",
			pointerSize, endian, version, path);
	}

	//---------------------------------------------------------------------------------------------

	private static GoBuildInfo readStringInfo(BinaryReader reader, boolean inlineStr,
			Program program, int ptrSize) throws IOException {

		String moduleString;
		String versionString;

		if (inlineStr) {
			reader.setPointerIndex(32 /* static start of inline strings */);

			versionString = reader.readNext(GoBuildInfo::varlenString);
			byte[] moduleStringBytes = reader.readNext(GoBuildInfo::varlenBytes);

			moduleString = extractModuleString(moduleStringBytes);
		}
		else {
			reader.setPointerIndex(16 /* static start of 2 string pointers */);
			long versionStrOffset = reader.readNextUnsignedValue(ptrSize);
			long moduleStrOffset = reader.readNextUnsignedValue(ptrSize);

			MemoryByteProvider memBP = new MemoryByteProvider(program.getMemory(),
				program.getImageBase().getAddressSpace());
			BinaryReader fullReader = new BinaryReader(memBP, reader.isLittleEndian());

			fullReader.setPointerIndex(versionStrOffset);
			versionString = readGoString(fullReader, ptrSize);

			fullReader.setPointerIndex(moduleStrOffset);
			byte[] moduleStrBytes = readRawGoString(fullReader, ptrSize);
			moduleString = extractModuleString(moduleStrBytes);
		}

		return parseBuildInfo(ptrSize, reader.isBigEndian() ? Endian.BIG : Endian.LITTLE,
			versionString, moduleString);
	}

	private static GoBuildInfo parseBuildInfo(int pointerSize, Endian endian, String versionString,
			String moduleString) throws IOException {
		String path = null;
		GoModuleInfo module = null;
		List<GoModuleInfo> deps = new ArrayList<>();
		List<GoBuildSettings> buildSettings = new ArrayList<>();

		String[] lines = moduleString.split("\n");
		for (int lineNum = 0; lineNum < lines.length; lineNum++) {
			String line = lines[lineNum];
			String replaceInfo =
				(lineNum + 1 < lines.length && lines[lineNum + 1].startsWith("=>\t"))
						? lines[++lineNum].substring(3)
						: null;

			if (line.isBlank()) {
				continue;
			}

			/*
			 * lines start with key of "path", "mod", "dep", "=>" (replacement info attached 
			 * to previous line), and "build"
			 */
			String[] lineParts = line.split("\t", 2);
			switch (lineParts[0]) {
				case "path":
					path = lineParts[1];
					break;
				case "mod": {
					GoModuleInfo replace = replaceInfo != null
							? GoModuleInfo.fromString(replaceInfo, null)
							: null;
					module = GoModuleInfo.fromString(lineParts[1], replace);
					break;
				}
				case "dep": {
					GoModuleInfo dep = GoModuleInfo.fromString(lineParts[1], null);
					deps.add(dep);
					break;
				}
				case "build":
					GoBuildSettings build = GoBuildSettings.fromString(lineParts[1]);
					buildSettings.add(build);
					break;
			}
		}

		if (versionString.startsWith("go")) {
			versionString = versionString.substring(2); // skip the "go"
		}

		return new GoBuildInfo(pointerSize, endian, versionString, path, module, deps,
			buildSettings);
	}

	private static String extractModuleString(byte[] bytes) throws IOException {
		int sentLen = INFOSTART_SENTINEL.length; // both are same len
		if (bytes.length < sentLen * 2) {
			return "";
		}

		int sentEndStart = bytes.length - sentLen;
		if (!Arrays.equals(INFOSTART_SENTINEL, 0, sentLen, bytes, 0, sentLen) ||
			!Arrays.equals(INFOEND_SENTINEL, 0, sentLen, bytes, sentEndStart, bytes.length)) {
			throw new IOException("bad sentinel");
		}
		return new String(bytes, sentLen, bytes.length - (sentLen * 2), StandardCharsets.UTF_8);

	}

	/**
	 * Reads a pascal-ish string used by go in lower level file format.
	 * <p>
	 * Not to be confused with a real golang string produced when strings are created in 
	 * a golang program. 
	 * 
	 * @param reader BinaryReader
	 * @return string at the current index of the BinaryReader
	 * @throws IOException if error
	 */
	private static String varlenString(BinaryReader reader) throws IOException {
		byte[] bytes = varlenBytes(reader);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/**
	 * Reads a variable length byte array.
	 * 
	 * @param reader BinaryReader
	 * @return variable length byte array at the current index of the BinaryReader
	 * @throws IOException if error
	 */
	private static byte[] varlenBytes(BinaryReader reader) throws IOException {
		int strLen = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		byte[] bytes = reader.readNextByteArray(strLen);
		return bytes;
	}

	private static String readGoString(BinaryReader reader, int ptrSize) throws IOException {
		byte[] bytes = readRawGoString(reader, ptrSize);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/**
	 * Low-level reading a golang string structure (without using rtti info).
	 * 
	 * @param reader BinaryReader that has access to the program's entire address space  
	 * @param ptrSize size of golang pointers
	 * @return bytes of the string
	 * @throws IOException if error reading the bytes
	 */
	private static byte[] readRawGoString(BinaryReader reader, int ptrSize) throws IOException {
		// struct { void *; long len }
		long dataAddr = reader.readNextUnsignedValue(ptrSize);
		long dataLen = reader.readNextUnsignedValue(ptrSize);
		if (dataAddr == 0 || dataLen == 0) {
			return new byte[0];
		}

		byte[] bytes = reader.readByteArray(dataAddr, (int) dataLen);
		return bytes;
	}

}
