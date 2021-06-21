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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Conv;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the 
 * <code>ImgDelayDescr</code>
 * data structure defined in <b><code>DELAYIMP.H</code></b>.
 * <p>
 * <pre>
 * typedef struct ImgDelayDescr {
 *     DWORD           grAttrs;        // attributes
 *     LPCSTR          szName;         // pointer to dll name
 *     HMODULE *       phmod;          // address of module handle
 *     PImgThunkData   pIAT;           // address of the IAT
 *     PCImgThunkData  pINT;           // address of the INT
 *     PCImgThunkData  pBoundIAT;      // address of the optional bound IAT
 *     PCImgThunkData  pUnloadIAT;     // address of optional copy of original IAT
 *     DWORD           dwTimeStamp;    // 0 if not bound,
 *                                     // O.W. date/time stamp of DLL bound to (old BIND)
 * } ImgDelayDescr, * PImgDelayDescr;
 * </pre>
 */
public class DelayImportDescriptor implements StructConverter {
	public final static String NAME = "ImgDelayDescr";

	private int grAttrs;
	private long szName;
	private long phmod;
	private long pIAT;
	private long pINT;
	private long pBoundIAT;
	private long pUnloadIAT;
	private int dwTimeStamp;

	private String dllName;

	private List<ThunkData> thunksIAT = new ArrayList<ThunkData>();
	private List<ThunkData> thunksINT = new ArrayList<ThunkData>();
	private List<ThunkData> thunksBoundIAT = new ArrayList<ThunkData>();
	private List<ThunkData> thunksUnloadIAT = new ArrayList<ThunkData>();

	private List<ImportInfo> delayImportInfoList = new ArrayList<ImportInfo>();
	private Map<ThunkData, ImportByName> importByNameMap = new HashMap<ThunkData, ImportByName>();
	
	private boolean isValid;

	static DelayImportDescriptor createDelayImportDescriptor(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader, int index) throws IOException {
		DelayImportDescriptor delayImportDescriptor =
			(DelayImportDescriptor) reader.getFactory().create(DelayImportDescriptor.class);
		delayImportDescriptor.initDelayImportDescriptor(ntHeader, reader, index);
		return delayImportDescriptor;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DelayImportDescriptor() {
	}

	private void initDelayImportDescriptor(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader, int index) throws IOException {
		
        if (!ntHeader.checkPointer(index)) {
			Msg.error(this, "Invalid file index for " + Integer.toHexString(index));
			return;
        }

		readFields(reader, index);
		readName(ntHeader, reader);

		thunksIAT = readThunks(ntHeader, reader, pIAT, false);
		if (thunksIAT == null) {
			return;
		}
		thunksINT = readThunks(ntHeader, reader, pINT, true);
		if (thunksINT == null) {
			return;
		}
		thunksBoundIAT = readThunks(ntHeader, reader, pBoundIAT, false);
		if (thunksBoundIAT == null) {
			return;
		}
		thunksUnloadIAT = readThunks(ntHeader, reader, pUnloadIAT, false);
		if (thunksUnloadIAT == null) {
			return;
		}
		isValid = true;
	}

	private List<ThunkData> readThunks(NTHeader ntHeader, FactoryBundledWithBinaryReader reader,
			long ptr, boolean isName) throws IOException {
		List<ThunkData> thunkList = new ArrayList<ThunkData>();
		if (ptr == 0) {
			return thunkList;
		}

		long thunkPtr = 0;
		int offset = 0;

		if (isUsingRVA()) {
			thunkPtr = ntHeader.rvaToPointer(ptr);
		}
		else {
			thunkPtr = ntHeader.vaToPointer(ptr);
		}

		while (true) {
			if (!ntHeader.checkPointer(thunkPtr)) {
				Msg.error(this, "Invalid thunkPtr for "+Long.toHexString(ptr));
				return null;
			}
			ThunkData thunk =
				ThunkData.createThunkData(reader, (int) thunkPtr,
					ntHeader.getOptionalHeader().is64bit());
			thunkList.add(thunk);
			if (thunk.getAddressOfData() == 0)
				break;

			thunkPtr += thunk.getStructSize();

			if (!isName) {
				continue;
			}

			String funcName;
			if (thunk.isOrdinal()) {
				funcName = SymbolUtilities.ORDINAL_PREFIX + thunk.getOrdinal();
			}
			else {
				long ibnPtr = 0;
				if (isUsingRVA()) {
					ibnPtr = ntHeader.rvaToPointer(thunk.getAddressOfData());
				}
				else {
					ibnPtr = ntHeader.vaToPointer(thunk.getAddressOfData());
				}
				if (ibnPtr < 0) {
					Msg.error(this, "Invalid import pointer for "+thunk.getAddressOfData());
					return thunkList;
				}
				ImportByName ibn = ImportByName.createImportByName(reader, (int) ibnPtr);
				importByNameMap.put(thunk, ibn);
				funcName = ibn.getName();
				thunk.setImportByName(ibn);
			}

			delayImportInfoList.add(new ImportInfo(offset, "", dllName, funcName, false));
			offset += thunk.getStructSize();
		}

		return thunkList;
	}

	private void readName(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		if (szName == 0) {
			return;
		}
		long namePtr =
			(isUsingRVA() ? ntHeader.rvaToPointer(szName) : ntHeader.vaToPointer(szName));
		if (!ntHeader.checkPointer(namePtr)) {
			Msg.warn(this, "Invalid namePtr for "+Long.toHexString(szName));
			return;
		}
		dllName = reader.readAsciiString((int) namePtr);
	}

	private void readFields(FactoryBundledWithBinaryReader reader, int index) throws IOException {
		grAttrs = reader.readInt(index);
		index += BinaryReader.SIZEOF_INT;
		szName = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		phmod = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		pIAT = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		pINT = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		pBoundIAT = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		pUnloadIAT = reader.readInt(index) & Conv.INT_MASK;
		index += BinaryReader.SIZEOF_INT;
		dwTimeStamp = reader.readInt(index);
		index += BinaryReader.SIZEOF_INT;
	}

	/**
	 * Returns true if the "using relative virtual address" is flag is set
	 * @return true if the "using relative virtual address" is flag is set
	 */
	public boolean isUsingRVA() {
		return (grAttrs & 1) == 1;
	}

	/**
	 * Returns the attributes.
	 * @return the attributes
	 */
	public int getAttibutes() {
		return grAttrs;
	}

	/**
	 * Returns the pointer to the DLL name.
	 * @return the pointer to the DLL name
	 */
	public long getPointerToDLLName() {
		return szName;
	}

	/**
	 * Returns the address of the module handle.
	 * @return the address of the module handle
	 */
	public long getAddressOfModuleHandle() {
		return phmod;
	}

	/**
	 * Returns the address of the import address table.
	 * @return the address of the import address table
	 */
	public long getAddressOfIAT() {
		return pIAT;
	}

	/**
	 * Returns the address of the import name table.
	 * @return the address of the import name table
	 */
	public long getAddressOfINT() {
		return pINT;
	}

	/**
	 * Returns the address of the optional bound IAT.
	 * @return the address of the optional bound IAT
	 */
	public long getAddressOfBoundIAT() {
		return pBoundIAT;
	}

	/**
	 * Returns the address of the optional copy of original IAT.
	 * @return the address of the optional copy of original IAT
	 */
	public long getAddressOfOriginalIAT() {
		return pUnloadIAT;
	}

	/**
	 * Returns the date/time stamp of DLL bound to (Old BIND),
	 * otherwise 0 if not bound.
	 * @return if bound returns the time stamp, otherwise 0
	 */
	public int getTimeStamp() {
		return dwTimeStamp;
	}

	/**
	 * Returns the DLL name.
	 * @return the DLL name
	 */
	public String getDLLName() {
		return dllName;
	}

	public Map<ThunkData, ImportByName> getImportByNameMap() {
		return new HashMap<ThunkData, ImportByName>(importByNameMap);
	}

	public List<ImportInfo> getImportList() {
		return new ArrayList<ImportInfo>(delayImportInfoList);
	}

	public List<ThunkData> getThunksIAT() {
		return new ArrayList<ThunkData>(thunksIAT);
	}

	public List<ThunkData> getThunksINT() {
		return new ArrayList<ThunkData>(thunksINT);
	}

	public List<ThunkData> getThunksBoundIAT() {
		return new ArrayList<ThunkData>(thunksBoundIAT);
	}

	public List<ThunkData> getThunksUnloadIAT() {
		return new ArrayList<ThunkData>(thunksUnloadIAT);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType ibo32 = new ImageBaseOffset32DataType();
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "grAttrs", null);
		struct.add(ibo32, "szName", null);
		struct.add(ibo32, "phmod", null);
		struct.add(ibo32, "pIAT", null);
		struct.add(ibo32, "pINT", null);
		struct.add(ibo32, "pBoundIAT", null);
		struct.add(ibo32, "pUnloadIAT", null);
		struct.add(DWORD, "dwTimeStamp", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * Returns the size of this structure. It accounts for 32 vs 64 bit.
	 * @return the size of this structure
	 */
	public int sizeof() {
		return 32;
	}

	public boolean isValid() {
		return isValid;
	}

}
