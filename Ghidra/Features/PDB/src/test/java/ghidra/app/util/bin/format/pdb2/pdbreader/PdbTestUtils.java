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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;

/**
 * Utilities in support of testing PdbReader and PdbApplicator.
 *
 */
public class PdbTestUtils {

	/**
	 * Creates an {@link ImageSectionHeader} from parameters. Non-listed parameters are set to zero
	 * @param pdb PDB that the ImageSectionHeader belongs to
	 * @param name of the section (must be 7 characters or less)
	 * @param virtualAddress DWORD (unsigned 32-bit) virtual address passed in as a long
	 * @param rawDataSize DWORD (unsigned 32-bit) data size passed in as a long
	 * @return the initialized ImageSectionHeader
	 */
	public static ImageSectionHeader createImageSectionHeader(AbstractPdb pdb, String name,
			long virtualAddress, long rawDataSize) {
		return createImageSectionHeader(pdb, name, 0L, virtualAddress, rawDataSize, 0L, 0L, 0L, 0,
			0, 0L);
	}

	/**
	 * Creates an {@link ImageSectionHeader} from parameters
	 * @param pdb PDB that the ImageSectionHeader belongs to
	 * @param name of the section (must be 7 characters or less)
	 * @param unionPAVS a unionPAVS value
	 * @param virtualAddress DWORD (unsigned 32-bit) virtual address passed in as a long
	 * @param rawDataSize DWORD (unsigned 32-bit) data size passed in as a long
	 * @param rawDataPointer DWORD (unsigned 32-bit) data pointer passed in as a long
	 * @param relocationsPointer DWORD (unsigned 32-bit) relocation pointer passed in as a long
	 * @param lineNumbersPointer DWORD (unsigned 32-bit) line numbers pointer passed in as a long
	 * @param numRelocations WORD (unsigned 16-bit) number of relocations passed in as an int
	 * @param numLineNumbers WORD (unsigned 16-bit) num line numbers passed in as an int
	 * @param characteristics DWORD (unsigned 32-bit) characteristics passed in as a long
	 * @return initialized ImageSectionHeader
	 */
	public static ImageSectionHeader createImageSectionHeader(AbstractPdb pdb, String name,
			long unionPAVS, long virtualAddress, long rawDataSize, long rawDataPointer,
			long relocationsPointer, long lineNumbersPointer, int numRelocations,
			int numLineNumbers, long characteristics) {

		int len = name.length();
		if (len > 7) {
			fail("ImageSectionHeader name to long for creation");
		}

		PdbByteWriter writer = new PdbByteWriter();
		writer.putNullTerminatedString(name);
		if (len < 7) {
			byte[] pad = new byte[7 - len];
			while (len < 7) {
				pad[6 - len++] = 0;
			}
			writer.putBytes(pad);
		}

		writer.putUnsignedInt(unionPAVS);
		writer.putUnsignedInt(virtualAddress);
		writer.putUnsignedInt(rawDataSize);
		writer.putUnsignedInt(rawDataPointer);
		writer.putUnsignedInt(relocationsPointer);
		writer.putUnsignedInt(lineNumbersPointer);
		writer.putUnsignedShort(numRelocations);
		writer.putUnsignedShort(numLineNumbers);
		writer.putUnsignedInt(characteristics);

		ImageSectionHeader header = new ImageSectionHeader(pdb);
		PdbByteReader reader = new PdbByteReader(writer.get());
		try {
			header.parse(reader);
		}
		catch (PdbException e) {
			e.printStackTrace();
			fail("Failed to initialize ImageSectionHeader during parse");
		}

		// Sanity check by reading values back out.
		assertEquals(name, header.getName());
		assertEquals(unionPAVS, header.getUnionPAVS());
		assertEquals(virtualAddress, header.getVirtualAddress());
		assertEquals(rawDataSize, header.getRawDataSize());
		assertEquals(rawDataPointer, header.getRawDataPointer());
		assertEquals(relocationsPointer, header.getRelocationsPointer());
		assertEquals(lineNumbersPointer, header.getLineNumbersPointer());
		assertEquals(numRelocations, header.getNumRelocations());
		assertEquals(numLineNumbers, header.getNumLineNumbers());
		assertEquals(characteristics, header.getCharacteristics());

		return header;
	}

	/**
	 * Create an {@link SegmentMapDescription} from parameters.  Non-listed parameters are set to
	 * zero or similar values
	 * @param pdb PDB that the SegmentMapDescription belongs to
	 * @param segOffset DWORD (unsigned 32-bit) segment offset passed in as an long
	 * @param segLength DWORD (unsigned 32-bit) segment length passed in as an long
	 * @return initialized SegmentMapDescription
	 */
	public static SegmentMapDescription createSegmentMapDescription(AbstractPdb pdb, long segOffset,
			long segLength) {
		return createSegmentMapDescription(pdb, 0, 0, 0, 0, 0xffff, 0xffff, segOffset, segLength);
	}

	/**
	 * Creates an {@link SegmentMapDescription} from parameters
	 * @param pdb PDB that the SegmentMapDescription belongs to
	 * @param flags WORD (unsigned 16-bit) flags passed in as an int
	 * @param ovl WORD (unsigned 16-bit) ovl passed in as an int
	 * @param group WORD (unsigned 16-bit) group passed in as an int
	 * @param frame WORD (unsigned 16-bit) frame passed in as an int
	 * @param segNameIndex WORD (unsigned 16-bit) segment name index passed in as an int
	 * @param classNameIndex WORD (unsigned 16-bit) class name index passed in as an int
	 * @param segOffset DWORD (unsigned 32-bit) segment offset passed in as an long
	 * @param segLength DWORD (unsigned 32-bit) segment length passed in as an long
	 * @return initialized SegmentMapDescription
	 */
	public static SegmentMapDescription createSegmentMapDescription(AbstractPdb pdb, int flags,
			int ovl, int group, int frame, int segNameIndex, int classNameIndex, long segOffset,
			long segLength) {

		PdbByteWriter writer = new PdbByteWriter();

		writer.putUnsignedShort(flags);
		writer.putUnsignedShort(ovl);
		writer.putUnsignedShort(group);
		writer.putUnsignedShort(frame);
		writer.putUnsignedShort(segNameIndex);
		writer.putUnsignedShort(classNameIndex);
		writer.putUnsignedInt(segOffset);
		writer.putUnsignedInt(segLength);

		SegmentMapDescription segmentMapDescription = new SegmentMapDescription();
		PdbByteReader reader = new PdbByteReader(writer.get());
		try {
			segmentMapDescription.deserialize(reader);
		}
		catch (PdbException e) {
			e.printStackTrace();
			fail("Failed to initialize SegmentMapDescription during parse");
		}

		assertEquals(flags, segmentMapDescription.getFlags());
		assertEquals(ovl, segmentMapDescription.getOvl());
		assertEquals(group, segmentMapDescription.getGroup());
		assertEquals(frame, segmentMapDescription.getFrame());
		assertEquals(segNameIndex, segmentMapDescription.getSegNameIndex());
		assertEquals(classNameIndex, segmentMapDescription.getClassNameIndex());
		assertEquals(segOffset, segmentMapDescription.getSegmentOffset());
		assertEquals(segLength, segmentMapDescription.getLength());

		return segmentMapDescription;
	}

	/**
	 * Creates an {@link PeCoffSectionMsSymbol} from parameters.  Non-listed parameters are set to
	 * zero or similar values
	 * @param pdb PDB that the PeCoffSectionMsSymbol belongs to
	 * @param sectionNumber WORD (unsigned 16-bit) segment name index passed in as an int
	 * @param rva relative virtual address of the section (DWORD (unsigned 32-bit)) so pass
	 * appropriate negative value that has same bytes as what would be the unsigned bytes)
	 * @param length the length of the section  (DWORD (unsigned 32-bit)) so pass appropriate
	 * negative value that has same bytes as what would be the unsigned bytes)
	 * @param name name of the section (believe UTF8 is charset)
	 * @return initialized PeCoffSectionMsSymbol
	 */
	public static PeCoffSectionMsSymbol createPeCoffSectionMsSymbol(AbstractPdb pdb,
			int sectionNumber, int rva, int length, String name) {
		return createPeCoffSectionMsSymbol(pdb, sectionNumber, 0, 0, rva, length, 0, name);
	}

	// Taken from SymbolsTest.testPeCoffSectionMsSymbol().
	// Envisioning future of moving this and all other "writer" mechanisms used in tests (symbols,
	// data types, etc) into additional utility classes.  Might then rename this containing class
	// (PdbTestUtils) to something more specific to the classes it helps with testing.
	// ALTERNATIVELY, We could modify target classes to have "write" capability, writing back
	// to a PdbByteWriter; move PdbByteWriter from test packages to reader packages and actually
	// rename from PdbReader some PdbReaderWriter or something more simple.  If we do this, then
	// we also need to deal with the try/catch exception differently.
	// Note that we would also have to decide where the PDB_ID is written.  Might be in an outer
	// method, but our other tests that call into the big switch parser are putting the value.
	// This is: writer.putUnsignedShort(PeCoffSectionMsSymbol.PDB_ID);

	/**
	 * Creates an {@link PeCoffSectionMsSymbol} from parameters
	 * @param pdb PDB that the PeCoffSectionMsSymbol belongs to
	 * @param sectionNumber WORD (unsigned 16-bit) segment name index passed in as an int
	 * @param align BYTE (unsigned 8-bit) segment name index passed in as a short
	 * @param reserved BYTE (unsigned 8-bit) segment name index passed in as a short
	 * @param rva relative virtual address of the section (DWORD (unsigned 32-bit)) so pass
	 * appropriate negative value that has same bytes as what would be the unsigned bytes)
	 * @param length the length of the section  (DWORD (unsigned 32-bit)) so pass appropriate
	 * negative value that has same bytes as what would be the unsigned bytes)
	 * @param characteristics the characteristics of the section  (DWORD (unsigned 32-bit)) so pass
	 * appropriate negative value that has same bytes as what would be the unsigned bytes)
	 * @param name name of the section (believe UTF8 is charset)
	 * @return initialized PeCoffSectionMsSymbol
	 */
	public static PeCoffSectionMsSymbol createPeCoffSectionMsSymbol(AbstractPdb pdb,
			int sectionNumber, int align, int reserved, int rva, int length, int characteristics,
			String name) {

		assertEquals(reserved, 0); // Must be zero

		PdbByteWriter writer = new PdbByteWriter();

		writer.putUnsignedShort(sectionNumber);
		writer.putUnsignedByte(align);
		writer.putUnsignedByte(reserved);
		writer.putUnsignedInt(rva);
		writer.putUnsignedInt(length);
		writer.putUnsignedInt(characteristics);
		writer.putNullTerminatedUtf8String(name);
		writer.putAlign(0);

		PdbByteReader reader = new PdbByteReader(writer.get());
		PeCoffSectionMsSymbol peCoffSectionMsSymbol = null;
		try {
			peCoffSectionMsSymbol = new PeCoffSectionMsSymbol(pdb, reader);
		}
		catch (PdbException e) {
			e.printStackTrace();
			fail("Failed to construct PeCoffSectionMsSymbol");
		}

		assertEquals(reader.getLimit(), writer.getSize()); // assuring properly putAlign() argument

		assertEquals(sectionNumber, peCoffSectionMsSymbol.getSectionNumber());
		assertEquals(align, peCoffSectionMsSymbol.getAlign());
		assertEquals(reserved, peCoffSectionMsSymbol.getReserved());
		assertEquals(rva, peCoffSectionMsSymbol.getRva());
		assertEquals(length, peCoffSectionMsSymbol.getLength());
		assertEquals(characteristics, peCoffSectionMsSymbol.getCharacteristics());
		assertEquals(name, peCoffSectionMsSymbol.getName());

		return peCoffSectionMsSymbol;
	}

	/**
	 * Packs an unsigned int (java long) with values from the parameters here.
	 * @param language the language
	 * @param compiledForEditAndContinue true if compiled for edit-and-continue
	 * @param notCompiledWithDebugInfo true if <b>not</b> compiled with debug info
	 * @param compiledWithLinkTimeCodeGeneration true if compiled with link-time code generation
	 * @param compiledWithBzalignNoDataAlign true if compiled with BS align no data align
	 * @param managedCodeDataPresent true if managed code data is present
	 * @param compiledWithGsBufferSecurityChecks true if compiled with GS Buffer security checks
	 * @param compiledWithHotPatch true if compiled with ability to hot-patch
	 * @param convertedWithCvtcil true if converted from (.NET IL) Common Intermediate Language Module
	 * @param microsoftIntermediateLanguageNetModule true if MSFT intermediate language net module
	 * @param compiledWithSdl true if compiled with SDL
	 * @param compiledWithLtcgPgoOrPgu true if compiled with light PGO or PGU
	 * @param dotExpModule true if dot exp module
	 * @return the flags packed into single integral form/value
	 */
	public long buildCompile3MsSymbolFlags(LanguageName language,
			boolean compiledForEditAndContinue, boolean notCompiledWithDebugInfo,
			boolean compiledWithLinkTimeCodeGeneration, boolean compiledWithBzalignNoDataAlign,
			boolean managedCodeDataPresent, boolean compiledWithGsBufferSecurityChecks,
			boolean compiledWithHotPatch, boolean convertedWithCvtcil,
			boolean microsoftIntermediateLanguageNetModule, boolean compiledWithSdl,
			boolean compiledWithLtcgPgoOrPgu, boolean dotExpModule) {
		return 0L;
	}

	/**
	 * Creates an {@link Compile3MsSymbol} from parameters.  Non-listed parameters are set to
	 * zero or similar values
	 * @param pdb PDB that the Compile3MsSymbol belongs to
	 * @param compilerVersionString the compiler version string
	 * @return initialized Compile3MsSymbol
	 */
	public static Compile3MsSymbol createCompile3MsSymbol(AbstractPdb pdb,
			String compilerVersionString) {
		return createCompile3MsSymbol(pdb, 0L, Processor.X64_AMD64, 0, 0, 0, 0, 0, 0, 0, 0,
			compilerVersionString);
	}

	/**
	 * Creates an {@link Compile3MsSymbol} from parameters
	 * @param pdb PDB that the Compile3MsSymbol belongs to
	 * @param flags the packed flags (see buildCompile3MsSymbolFlags) unsigned int stored in long
	 * @param processor the processor value
	 * @param frontEndMajorVersionNumber the front end major version number
	 * @param frontEndMinorVersionNumber the front end minor version number
	 * @param frontEndBuildVersionNumber the front end build version number
	 * @param frontEndQuickFixEngineeringVersionNumber the front end quick-fix version number
	 * @param backEndMajorVersionNumber the back end major version number
	 * @param backEndMinorVersionNumber the back end minor version number
	 * @param backEndBuildVersionNumber the back end build version number
	 * @param backEndQuickFixEngineeringVersionNumber the back end quick-fix version number
	 * @param compilerVersionString the compiler version string
	 * @return initialized Compile3MsSymbol
	 */
	public static Compile3MsSymbol createCompile3MsSymbol(AbstractPdb pdb, long flags,
			Processor processor, int frontEndMajorVersionNumber, int frontEndMinorVersionNumber,
			int frontEndBuildVersionNumber, int frontEndQuickFixEngineeringVersionNumber,
			int backEndMajorVersionNumber, int backEndMinorVersionNumber,
			int backEndBuildVersionNumber, int backEndQuickFixEngineeringVersionNumber,
			String compilerVersionString) {

		PdbByteWriter writer = new PdbByteWriter();

		writer.putUnsignedInt(flags);
		writer.putUnsignedShort(processor.getValue());
		writer.putUnsignedShort(frontEndMajorVersionNumber);
		writer.putUnsignedShort(frontEndMinorVersionNumber);
		writer.putUnsignedShort(frontEndBuildVersionNumber);
		writer.putUnsignedShort(frontEndQuickFixEngineeringVersionNumber);
		writer.putUnsignedShort(backEndMajorVersionNumber);
		writer.putUnsignedShort(backEndMinorVersionNumber);
		writer.putUnsignedShort(backEndBuildVersionNumber);
		writer.putUnsignedShort(backEndQuickFixEngineeringVersionNumber);
		writer.putNullTerminatedUtf8String(compilerVersionString);

		PdbByteReader reader = new PdbByteReader(writer.get());

		Compile3MsSymbol compile3MsSymbol = null;
		try {
			compile3MsSymbol = new Compile3MsSymbol(pdb, reader);
		}
		catch (PdbException e) {
			e.printStackTrace();
			fail("Failed to construct Compile3MsSymbol");
		}

		assertEquals(reader.getLimit(), writer.getSize());

		assertEquals(flags, compile3MsSymbol.getFlags());
		assertEquals(frontEndMajorVersionNumber, compile3MsSymbol.getFrontEndMajorVersionNumber());
		assertEquals(frontEndMinorVersionNumber, compile3MsSymbol.getFrontEndMinorVersionNumber());
		assertEquals(frontEndBuildVersionNumber, compile3MsSymbol.getFrontEndBuildVersionNumber());
		assertEquals(frontEndQuickFixEngineeringVersionNumber,
			compile3MsSymbol.getFrontEndQuickFixEngineeringVersionNumber());
		assertEquals(backEndMajorVersionNumber, compile3MsSymbol.getBackEndMajorVersionNumber());
		assertEquals(backEndMinorVersionNumber, compile3MsSymbol.getBackEndMinorVersionNumber());
		assertEquals(backEndBuildVersionNumber, compile3MsSymbol.getBackEndBuildVersionNumber());
		assertEquals(backEndQuickFixEngineeringVersionNumber,
			compile3MsSymbol.getBackEndQuickFixEngineeringVersionNumber());
		assertEquals(compilerVersionString, compile3MsSymbol.getCompilerVersionString());

		// Very important: Store target machine information.  It is used elsewhere, including
		// in RegisterName. I think it is just as important here, but maybe should allow
		// reader to set the value, but for testing, that part of the code might not be activated,
		// as we might only be testing small portions of the reader
		pdb.setTargetProcessor(processor);

		return compile3MsSymbol;
	}
}
