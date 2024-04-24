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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * A low-level structure embedded in golang binaries that contains useful bootstrapping
 * information.
 * <p>
 * 
 */
@StructureMapping(structureName = "runtime.pcHeader")
public class GoPcHeader {
	private static final String RUNTIME_PCLNTAB_SYMBOLNAME = "runtime.pclntab";
	public static final String GOPCLNTAB_SECTION_NAME = "gopclntab";
	public static final int GO_1_2_MAGIC = 0xfffffffb;
	public static final int GO_1_16_MAGIC = 0xfffffffa;
	public static final int GO_1_18_MAGIC = 0xfffffff0;

	/**
	 * Returns the {@link Address} (if present) of the go pclntab section or symbol.
	 *  
	 * @param program {@link Program}
	 * @return {@link Address} of go pclntab, or null if not present
	 */
	public static Address getPclntabAddress(Program program) {
		MemoryBlock pclntabBlock = GoRttiMapper.getGoSection(program, GOPCLNTAB_SECTION_NAME);
		if (pclntabBlock != null) {
			return pclntabBlock.getStart();
		}
		// PE binaries have a symbol instead of a named section
		Symbol pclntabSymbol = GoRttiMapper.getGoSymbol(program, RUNTIME_PCLNTAB_SYMBOLNAME);
		return pclntabSymbol != null
				? pclntabSymbol.getAddress()
				: null;
	}

	/**
	 * Returns true if the specified program has an easily found pclntab
	 * 
	 * @param program {@link Program}
	 * @return boolean true if program has a pclntab, false otherwise
	 */
	public static boolean hasPclntab(Program program) {
		Address addr = getPclntabAddress(program);
		if (addr != null) {
			try (ByteProvider provider = new MemoryByteProvider(program.getMemory(), addr)) {
				return isPclntab(provider);
			}
			catch (IOException e) {
				// fall thru
			}
		}
		return false;
	}

	/**
	 * Searches (possibly slowly) for a pclntab structure in the specified memory range, which
	 * is typically necessary in stripped PE binaries.
	 * 
	 * @param programContext {@link GoRttiMapper} 
	 * @param range memory range to search (typically .rdata or .noptrdata sections)
	 * @param monitor {@link TaskMonitor} that will let the user cancel
	 * @return {@link Address} of the found pclntab structure, or null if not found
	 * @throws IOException if error reading
	 */
	public static Address findPclntabAddress(GoRttiMapper programContext, AddressRange range,
			TaskMonitor monitor) throws IOException {
		if (range == null) {
			return null;
		}
		// search for magic signature + padding + wildcard_minLc + ptrSize
		byte[] searchBytes = new byte[/*4 + 2 + 1 + 1*/] {
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, // magic signature
			0, 0,	// padding
			0,	// unknown minLc, masked
			(byte) programContext.getPtrSize()	// ptrSize
		};
		byte[] searchMask = new byte[] {
			(byte) 0xf0, (byte) 0xff, (byte) 0xff, (byte) 0xf0, // magic, first byte nibble and last byte nibble is wildcard to handle either endian matching
			(byte) 0xff, (byte) 0xff,	// padding 
			0,	// unknown minLc - wildcarded
			(byte) 0xff // ptrSize 
		};
		Memory memory = programContext.getProgram().getMemory();
		Address pclntabAddr =
			memory.findBytes(range.getMinAddress(), range.getMaxAddress(), searchBytes, searchMask,
				true, monitor);
		if (pclntabAddr == null) {
			return null;
		}
		MemoryByteProvider bp =
			new MemoryByteProvider(memory, pclntabAddr, range.getMaxAddress());
		return isPclntab(bp) ? pclntabAddr : null;
	}

	/**
	 * Returns true if there is a pclntab at the current position of the specified ByteProvider.
	 * 
	 * @param provider {@link ByteProvider}
	 * @return boolean true if the byte provider has the magic signature of a pclntab
	 * @throws IOException if error reading
	 */
	public static boolean isPclntab(ByteProvider provider) throws IOException {
		byte[] header = provider.readBytes(0, 8);
		// logic from pclntab.go parsePclnTab()
		if (provider.length() < 16 ||
			header[4] != 0 || header[5] != 0 || // pad bytes == 0
			(header[6] != 1 && header[6] != 2 && header[6] != 4) || // minLc == 1,2,4
			(header[7] != 4 && header[7] != 8) // ptrSize == 4,8
		) {
			return false;
		}
		return readMagic(provider) != null;
	}

	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoPcHeader> context;

	@FieldMapping
	@EOLComment("getGoVersion")
	private int magic;

	@FieldMapping
	private byte minLC;

	@FieldMapping
	private byte ptrSize;

	@FieldMapping(optional = true) // present >= 1.18
	@MarkupReference
	private long textStart;	// should be same as offset of ".text"

	@FieldMapping
	@MarkupReference("getFuncnameAddress")
	private long funcnameOffset;

	@FieldMapping
	@MarkupReference("getCuAddress")
	private long cuOffset;

	@FieldMapping
	@MarkupReference("getFiletabAddress")
	private long filetabOffset;

	@FieldMapping
	@MarkupReference("getPctabAddress")
	private long pctabOffset;

	@FieldMapping
	@MarkupReference("getPclnAddress")
	private long pclnOffset;

	public GoVer getGoVersion() {
		// TODO: this might be better as a static helper method that can be used by multiple
		// GoPcHeader struct versions (if necessary)
		GoVer ver = switch (magic) {
			case GO_1_2_MAGIC -> GoVer.V1_2;
			case GO_1_16_MAGIC -> GoVer.V1_16;
			case GO_1_18_MAGIC -> GoVer.V1_18;
			default -> GoVer.UNKNOWN;
		};
		return ver;
	}

	/**
	 * Returns true if this pcln structure contains a textStart value (only present >= 1.18)
	 * @return
	 */
	public boolean hasTextStart() {
		return textStart != 0;
	}

	/**
	 * Returns the address of where the text area starts.
	 * 
	 * @return address of text starts
	 */
	public Address getTextStart() {
		return programContext.getDataAddress(textStart);
	}

	/**
	 * Returns address of the func name slice
	 * @return address of func name slice
	 */
	public Address getFuncnameAddress() {
		return programContext.getDataAddress(context.getStructureStart() + funcnameOffset);
	}

	/**
	 * Returns address of the cu tab slice, used by the cuOffset field's markup annotation.
	 * @return address of the cu tab slice
	 */
	public Address getCuAddress() {
		return programContext.getDataAddress(context.getStructureStart() + cuOffset);
	}

	/**
	 * Returns the address of the filetab slice, used by the filetabOffset field's markup annotation
	 * @return address of the filetab slice
	 */
	public Address getFiletabAddress() {
		return programContext.getDataAddress(context.getStructureStart() + filetabOffset);
	}

	/**
	 * Returns the address of the pctab slice, used by the pctabOffset field's markup annotation
	 * @return address of the pctab slice
	 */
	public Address getPctabAddress() {
		return programContext.getDataAddress(context.getStructureStart() + pctabOffset);
	}

	/**
	 * Returns the address of the pcln slice, used by the pclnOffset field's markup annotation
	 * @return address of the pcln slice
	 */
	public Address getPclnAddress() {
		return programContext.getDataAddress(context.getStructureStart() + pclnOffset);
	}

	/**
	 * Returns the min lc, used as the GoPcValueEvaluator's pcquantum
	 * @return minLc
	 */
	public byte getMinLC() {
		return minLC;
	}

	/**
	 * Returns the pointer size
	 * @return pointer size
	 */
	public byte getPtrSize() {
		return ptrSize;
	}

	//--------------------------------------------------------------------------------------------
	record GoVerEndian(GoVer goVer, Endian endian) {
		GoVerEndian(GoVer goVer, boolean isLittleEndian) {
			this(goVer, isLittleEndian ? Endian.LITTLE : Endian.BIG);
		}
	}

	private static GoVerEndian readMagic(ByteProvider provider) throws IOException {
		int leMagic = new BinaryReader(provider, true /* little endian */).readInt(0);
		int beMagic = new BinaryReader(provider, false /* big endian */).readInt(0);

		if (leMagic == GO_1_2_MAGIC || beMagic == GO_1_2_MAGIC) {
			return new GoVerEndian(GoVer.V1_2, leMagic == GO_1_2_MAGIC);
		}
		else if (leMagic == GO_1_16_MAGIC || beMagic == GO_1_16_MAGIC) {
			return new GoVerEndian(GoVer.V1_16, leMagic == GO_1_16_MAGIC);
		}
		else if (leMagic == GO_1_18_MAGIC || beMagic == GO_1_18_MAGIC) {
			return new GoVerEndian(GoVer.V1_18, leMagic == GO_1_18_MAGIC);
		}
		return null;
	}

}
/*
struct runtime.pcHeader  
Length: 40  Alignment: 4
{ 
  uint32    magic                   
  uint8      pad1                     
  uint8      pad2                     
  uint8      minLC                   
  uint8      ptrSize                  
  int          nfunc                    
  uint        nfiles                     
  uintptr  textStart               
  uintptr  funcnameOffset   
  uintptr  cuOffset                
  uintptr  filetabOffset          
  uintptr  pctabOffset          
  uintptr  pclnOffset             
} pack()
*/
