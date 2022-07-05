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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.BeforeClass;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.DummyMsType;

public class SymbolsTest extends AbstractGenericTest {

	private static AbstractPdb pdb;
	// Important: Must also use this processorIndex value in any tests below that need it to
	//  ensure consistency across the tests.  We are setting it in the pdb here (in the static
	//  assignment block), but we do not know the order that any tests are run, so having the
	//  same value  will ensure consistent results.
	private static Processor processor;

	@BeforeClass
	public static void setUp() {
		try (DummyPdb700 dummyPdb700 = new DummyPdb700(4096, 4096, 4096, 4096)) {
			pdb = dummyPdb700;
			processor = Processor.I8080;
			pdb.setTargetProcessor(processor);

			// Create records that will be used indirectly
			AbstractMsType type = new DummyMsType(pdb, null);
			AbstractMsType item = new DummyMsType(pdb, null, "Item");

			//=================================
			// TPI Records
			dummyPdb700.setTypeRecord(4096, type);

			//=================================
			// IPI Records
			dummyPdb700.setItemRecord(4096, item);
		}
		catch (Exception e) {
			fail("Error in static initialization of test: " + e);
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	@Test
	public void testInstructionAnnotationCodeOffsetSmallMin() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x00, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 0", result);
	}

	@Test
	public void testInstructionAnnotationCodeOffsetSmallMax() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x7f, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 7f", result);
	}

	@Test
	public void testInstructionAnnotationCodeOffsetMediumMin() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x80, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 80", result);
	}

	@Test
	public void testInstructionAnnotationCodeOffsetMediumMax() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x3fff, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 3fff", result);
	}

	@Test
	public void testInstructionAnnotationCodeOffsetLargeMin() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x4000, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 4000", result);
	}

	@Test
	public void testInstructionAnnotationCodeOffsetLarge() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x01, 0x1fffffff, 0x00);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  Offset 1fffffff", result);
	}

	@Test
	public void testInstructionAnnotationChangeCodeOffsetBase() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x02, 0x20, 0x21);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  CodeOffsetBase 20", result);
	}

	@Test
	public void testInstructionAnnotationChangeCodeOffset() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x03, 0x30, 0x31);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  CodeOffset 30", result);
	}

	@Test
	public void testInstructionAnnotationChangeCodeLength() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x04, 0x40, 0x41);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  CodeLength 40", result);
	}

	@Test
	public void testInstructionAnnotationChangeFile() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x05, 0x50, 0x51);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  File 50", result);
	}

	@Test
	public void testInstructionAnnotationChangeLineOffset() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x06, 0x60, 0x61);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  LineOffset 60", result);
	}

	@Test
	public void testInstructionAnnotationChangeLineEndDelta() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x07, 0x70, 0x71);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  LineEndDelta 70", result);
	}

	@Test
	public void testInstructionAnnotationChangeRangeKind() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x08, 0x80, 0x81);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  RangeKind 80", result);
	}

	@Test
	public void testInstructionAnnotationChangeColumnStart() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x09, 0x90, 0x91);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  ColumnStart 90", result);
	}

	@Test
	public void testInstructionAnnotationChangeColumnEndDelta() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x0a, 0xa0, 0xa1);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  ColumnEndDelta a0", result);
	}

	@Test
	public void testInstructionAnnotationChangeColumnEndDeltaNegValue() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x0a, -(0x40), 0xa1);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  ColumnEndDelta ffffffc0", result);
	}

	@Test
	public void testInstructionAnnotationChangeCodeOffsetAndLineOffset() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x0b, 0xb0, 0xb1);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  CodeOffsetAndLineOffset b 0", result);
	}

	@Test
	public void testInstructionAnnotationChangeCodeLengthAndCodeOffset() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x0c, 0xc0, 0xc1);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  CodeLengthAndCodeOffset c0 c1", result);
	}

	@Test
	public void testInstructionAnnotationChangeColumnEnd() throws Exception {
		byte[] buf = createInstructionAnnotationBuffer(0x0d, 0xd0, 0xd1);
		PdbByteReader reader = new PdbByteReader(buf);
		InstructionAnnotation annotation = new InstructionAnnotation(reader);
		String result = annotation.toString();
		assertEquals("  ColumnEnd d0", result);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	@Test
	public void testUnknownMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(0xffff);
		writer.putBytes(new byte[] { (byte) 0xfe, (byte) 0xfd, (byte) 0xfc }); // dummy data
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UnknownMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNKNOWN_SYMBOL (0XFFFF): Bytes:\n" + "000000 fe fd fc", result);
	}

	@Test
	public void testBadMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CompileFlagsMsSymbol.PDB_ID);
		writer.putUnsignedByte(0x00); // Processor value.
		// Incomplete record should cause BadMsSymbol to be created.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BadMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BAD_SYMBOL: ID=0X0001", result);
	}

	@Test
	public void testCompileFlagsMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CompileFlagsMsSymbol.PDB_ID);
		writer.putUnsignedByte(0x00); // Processor value.
		writer.putBytes(new byte[] { 0x00, 0x00, 0x00 }); // 3 bytes of flags
		writer.putByteLengthPrefixedString("CompilerVersionString");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CompileFlagsMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COMPILE:\n" + "   Language: C\n" + "   Target Processor: 8080\n" +
			"   Floating-point precision: 0\n" + "   Floating-point package: 0\n" +
			"   Ambiant data: 0\n" + "   Ambiant code: 0\n" + "   PCode present: no\n" +
			"   Version String:CompilerVersionString", result);
	}

	@Test
	public void testCompile2StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Compile2StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0); // flags
		writer.putUnsignedShort(processor.getValue()); // Processor value.
		writer.putUnsignedShort(0x0001); // front end major version number
		writer.putUnsignedShort(0x0002); // front end minor version number 
		writer.putUnsignedShort(0x0003); // front end build version number
		writer.putUnsignedShort(0x0004); // back end major version number
		writer.putUnsignedShort(0x0005); // back end minor version number 
		writer.putUnsignedShort(0x0006); // back end build version number
		writer.putByteLengthPrefixedUtf8String("CompilerVersionString"); // This is len pref.
		writer.putNullTerminatedUtf8String("optionalString1"); // These are null term.
		writer.putNullTerminatedUtf8String("optionalString2"); // These are null term.
		writer.putUnsignedByte(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Compile2StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COMPILE2_ST:\n" + "   Language: C\n" + "   Target Processor: 8080\n" +
			"   Compiled for edit and continue: no\n" + "   Compiled withoug debugging info: no\n" +
			"   Compiled with LTCG: no\n" + "   Compiled with /bzalign: no\n" +
			"   Managed code present: no\n" + "   Compiled with /GS: no\n" +
			"   Compiled with /hotpatch: no\n" + "   Converted by CVTCIL: no\n" +
			"   Microsoft Intermediate Language Module: no\n" +
			"   Frontend Version: Major = 1, Minor = 2, Build = 3\n" +
			"   Backend Version: Major = 4, Minor = 5, Build = 6\n" +
			"   Version String:CompilerVersionString\n" + "Command block: \n" +
			"   optionalString1 = 'optionalString2'", result);
	}

	@Test
	public void testCompile2MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Compile2MsSymbol.PDB_ID);
		writer.putUnsignedInt(0); // flags
		writer.putUnsignedShort(processor.getValue()); // Processor value.
		writer.putUnsignedShort(0x0001); // front end major version number
		writer.putUnsignedShort(0x0002); // front end minor version number 
		writer.putUnsignedShort(0x0003); // front end build version number
		writer.putUnsignedShort(0x0004); // back end major version number
		writer.putUnsignedShort(0x0005); // back end minor version number 
		writer.putUnsignedShort(0x0006); // back end build version number
		writer.putNullTerminatedUtf8String("CompilerVersionString"); // These are null term.
		writer.putNullTerminatedUtf8String("optionalString1"); // These are null term.
		writer.putNullTerminatedUtf8String("optionalString2"); // These are null term.
		writer.putUnsignedByte(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Compile2MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COMPILE2:\n" + "   Language: C\n" + "   Target Processor: 8080\n" +
			"   Compiled for edit and continue: no\n" + "   Compiled withoug debugging info: no\n" +
			"   Compiled with LTCG: no\n" + "   Compiled with /bzalign: no\n" +
			"   Managed code present: no\n" + "   Compiled with /GS: no\n" +
			"   Compiled with /hotpatch: no\n" + "   Converted by CVTCIL: no\n" +
			"   Microsoft Intermediate Language Module: no\n" +
			"   Frontend Version: Major = 1, Minor = 2, Build = 3\n" +
			"   Backend Version: Major = 4, Minor = 5, Build = 6\n" +
			"   Version String:CompilerVersionString\n" + "Command block: \n" +
			"   optionalString1 = 'optionalString2'", result);
	}

	@Test
	public void testCompile3MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Compile3MsSymbol.PDB_ID);
		writer.putUnsignedInt(0); // flags
		writer.putUnsignedShort(processor.getValue()); // Processor value.
		writer.putUnsignedShort(0x0001); // front end major version number
		writer.putUnsignedShort(0x0002); // front end minor version number 
		writer.putUnsignedShort(0x0003); // front end build version number
		writer.putUnsignedShort(0x0004); // front end QFE version number 
		writer.putUnsignedShort(0x0005); // back end major version number
		writer.putUnsignedShort(0x0006); // back end minor version number 
		writer.putUnsignedShort(0x0007); // back end build version number
		writer.putUnsignedShort(0x0008); // back end QFE version number 
		writer.putNullTerminatedUtf8String("CompilerVersionString"); // These are null term.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Compile3MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COMPILE3:\n" + "   Language: C\n" + "   Target Processor: 8080\n" +
			"   Compiled for edit and continue: no\n" + "   Compiled withoug debugging info: no\n" +
			"   Compiled with LTCG: no\n" + "   Compiled with /bzalign: no\n" +
			"   Managed code present: no\n" + "   Compiled with /GS: no\n" +
			"   Compiled with /hotpatch: no\n" + "   Converted by CVTCIL: no\n" +
			"   Microsoft Intermediate Language Module: no\n" + "   Compiled with /sdl: no\n" +
			"   Compiled with Profile Guided Optimization (PGO): no\n" + "   .EXP module: no\n" +
			"   Frontend Version: Major = 1, Minor = 2, Build = 3, QFE = 4\n" +
			"   Backend Version: Major = 5, Minor = 6, Build = 7, QFE = 8\n" +
			"   Version String:CompilerVersionString", result);
	}

	@Test
	public void testEnvironmentBlockMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnvironmentBlockMsSymbol.PDB_ID);
		writer.putUnsignedByte(0); // 1 if compiled for edit-and-continue debug
		writer.putNullTerminatedUtf8String("optionalString1");
		writer.putNullTerminatedUtf8String("optionalString2");
		writer.putNullTerminatedUtf8String("optionalString3");
		writer.putNullTerminatedUtf8String("optionalString4");
		writer.putUnsignedByte(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EnvironmentBlockMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ENVBLOCK:\n" + "Compiled for edit and continue: no\n" + "Command block: \n" +
			"   optionalString1 = 'optionalString2'\n" + "   optionalString3 = 'optionalString4'",
			result);
	}

	@Test
	public void testRegister16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Register16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index or metadata token
		writer.putUnsignedShort(0x0102); // Register enumerate
		writer.putByteLengthPrefixedUtf8String("registerSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Register16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGISTER_16: al:cl, Type: DummyMsType, registerSymbolName", result);
	}

	@Test
	public void testRegisterStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		writer.putUnsignedShort(0x01); // Register enumerate
		writer.putByteLengthPrefixedUtf8String("registerSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGISTER_ST: al, Type: DummyMsType, registerSymbolName", result);
	}

	@Test
	public void testRegisterMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		writer.putUnsignedShort(0x01); // Register enumerate
		writer.putNullTerminatedUtf8String("registerSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGISTER: al, Type: DummyMsType, registerSymbolName", result);
	}

	@Test
	public void testConstant16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Constant16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index containing enum if enumerate
		writer.putUnsignedShort(0x01); // Value
		writer.putByteLengthPrefixedUtf8String("constantSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Constant16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CONSTANT_16: Type: DummyMsType, Value: 1, constantSymbolName", result);
	}

	@Test
	public void testConstantStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ConstantStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putUnsignedShort(0x01); // Value
		writer.putByteLengthPrefixedUtf8String("constantSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ConstantStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CONSTANT_ST: Type: DummyMsType, Value: 1, constantSymbolName", result);
	}

	@Test
	public void testConstantMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ConstantMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putUnsignedShort(0x01); // Value
		writer.putNullTerminatedUtf8String("constantSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ConstantMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CONSTANT: Type: DummyMsType, Value: 1, constantSymbolName", result);
	}

	@Test
	public void testManagedConstantMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedConstantMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putUnsignedShort(0x01); // Value
		writer.putNullTerminatedUtf8String("constantSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedConstantMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANCONSTANT: Type: DummyMsType, Value: 1, constantSymbolName", result);
	}

	@Test
	public void testUserDefinedType16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UserDefinedType16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index containing enum if enumerate
		writer.putByteLengthPrefixedUtf8String("UDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UserDefinedType16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UDT_16: DummyMsType, UDTSymbolName", result);
	}

	@Test
	public void testUserDefinedTypeStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UserDefinedTypeStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putByteLengthPrefixedUtf8String("UDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UserDefinedTypeStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UDT_ST: DummyMsType, UDTSymbolName", result);
	}

	@Test
	public void testUserDefinedTypeMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UserDefinedTypeMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putNullTerminatedUtf8String("UDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UserDefinedTypeMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UDT: DummyMsType, UDTSymbolName", result);
	}

	@Test
	public void testCobolUserDefinedType16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CobolUserDefinedType16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index containing enum if enumerate
		writer.putByteLengthPrefixedUtf8String("CobolUDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CobolUserDefinedType16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COBOLUDT_16: DummyMsType, CobolUDTSymbolName", result);
	}

	@Test
	public void testCobolUserDefinedTypeStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CobolUserDefinedTypeStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putByteLengthPrefixedUtf8String("CobolUDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CobolUserDefinedTypeStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COBOLUDT_ST: DummyMsType, CobolUDTSymbolName", result);
	}

	@Test
	public void testCobolUserDefinedTypeMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CobolUserDefinedTypeMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putNullTerminatedUtf8String("CobolUDTSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CobolUserDefinedTypeMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COBOLUDT: DummyMsType, CobolUDTSymbolName", result);
	}

	@Test
	public void testStartSearchMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StartSearchMsSymbol.PDB_ID);
		writer.putInt(0x100); // Offset of the procedure
		writer.putUnsignedShort(0x1); // Setment of the symbol
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof StartSearchMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("Start search for segment 0x1 at 0x100", result);
	}

	@Test
	public void testEndMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EndMsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EndMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("END", result);
	}

	@Test
	public void testSkipMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SkipMsSymbol.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // Putting data, but might never be any.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof SkipMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("Skip Record, Length = 0x2", result);
	}

	@Test
	public void testCvReservedMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CvReservedMsSymbol.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // Putting data, but might never be any.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CvReservedMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CVRESERVE, Length = 0x2", result);
	}

	@Test
	public void testObjectNameStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ObjectNameStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putByteLengthPrefixedUtf8String("ObjectNameSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ObjectNameStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("OBJNAME_ST: Signature: 4096, ObjectNameSymbolName", result);
	}

	@Test
	public void testObjectNameMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ObjectNameMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index containing enum if enumerate
		writer.putNullTerminatedUtf8String("ObjectNameSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ObjectNameMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("OBJNAME: Signature: 4096, ObjectNameSymbolName", result);
	}

	@Test
	public void testEndArgumentsListMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EndArgumentsListMsSymbol.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // Putting data, but might never be any.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EndArgumentsListMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ENDARG, Length = 0x2", result);
	}

	@Test
	public void testManyRegisterVariable16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManyRegisterVariable16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index
		int count = 2;
		writer.putUnsignedByte(count);
		for (int i = 0; i < count; i++) {
			writer.putUnsignedByte(i + 1);
		}
		writer.putByteLengthPrefixedUtf8String("ManyRegisterVariableName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManyRegisterVariable16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANYREG_16: al, cl DummyMsType ManyRegisterVariableName", result);
	}

	@Test
	public void testManyRegisterVariableStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManyRegisterVariableStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		int count = 2;
		writer.putUnsignedByte(count);
		for (int i = 0; i < count; i++) {
			writer.putUnsignedByte(i + 1);
		}
		writer.putByteLengthPrefixedUtf8String("ManyRegisterVariableName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManyRegisterVariableStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANYREG_ST: al, cl DummyMsType ManyRegisterVariableName", result);
	}

	@Test
	public void testManyRegisterVariableMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManyRegisterVariableMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		int count = 2;
		writer.putUnsignedByte(count);
		for (int i = 0; i < count; i++) {
			writer.putUnsignedByte(i + 1);
		}
		writer.putNullTerminatedUtf8String("ManyRegisterVariableName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManyRegisterVariableMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANYREG: al, cl DummyMsType ManyRegisterVariableName", result);
	}

	@Test
	public void testManyRegisterVariable2StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManyRegisterVariable2StMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		int count = 2;
		writer.putUnsignedShort(count);
		for (int i = 0; i < count; i++) {
			writer.putUnsignedShort(i + 1);
		}
		writer.putByteLengthPrefixedUtf8String("ManyRegisterVariable2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManyRegisterVariable2StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANYREG2_ST: al, cl DummyMsType ManyRegisterVariable2Name", result);
	}

	@Test
	public void testManyRegisterVariable2MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManyRegisterVariable2MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index or metadata token
		int count = 2;
		writer.putUnsignedShort(count);
		for (int i = 0; i < count; i++) {
			writer.putUnsignedShort(i + 1);
		}
		writer.putNullTerminatedUtf8String("ManyRegisterVariable2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManyRegisterVariable2MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANYREG2: al, cl DummyMsType ManyRegisterVariable2Name", result);
	}

	@Test
	public void testReturnDescriptionMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ReturnDescriptionMsSymbol.PDB_ID);
		writer.putUnsignedShort(0x00); // Generic flags
		writer.putUnsignedByte(0x01); // Generic style.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ReturnDescriptionMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"RETURN, return data in registers, varargs left-to-right, caller cleans stack;" +
				" byte length of remaining method data = 0",
			result);
	}

	@Test
	public void testEntryThisMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EntryThisMsSymbol.PDB_ID);
		// API: "Symbol describing this pointer on entry" TODO: made up data; what should it be?
		writer.putUnsignedByte(0x55);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EntryThisMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ENTRYTHIS, 'this' symbol: 55; byte length of remaining data = 0", result);
	}

	@Test
	public void testBasePointerRelative16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasePointerRelative16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x10); // BasePointer-relative offset.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("BasePointerRelativeName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BasePointerRelative16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BPREL16: [00000010], Type: DummyMsType, BasePointerRelativeName", result);
	}

	@Test
	public void testBasePointerRelative3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasePointerRelative3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // BasePointer-relative offset.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("BasePointerRelativeName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BasePointerRelative3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BPREL32_16: [00000010], Type: DummyMsType, BasePointerRelativeName", result);
	}

	@Test
	public void testBasePointerRelative32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasePointerRelative32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // BasePointer-relative offset.
		writer.putInt(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("BasePointerRelativeName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BasePointerRelative32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BPREL32_ST: [00000010], Type: DummyMsType, BasePointerRelativeName", result);
	}

	@Test
	public void testBasePointerRelative32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasePointerRelative32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // BasePointer-relative offset.
		writer.putInt(4096); // Type index
		writer.putNullTerminatedUtf8String("BasePointerRelativeName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BasePointerRelative32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BPREL32: [00000010], Type: DummyMsType, BasePointerRelativeName", result);
	}

	@Test
	public void testLocalData16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalData16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("LocalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalData16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA16: [0001:00000010], Type: DummyMsType, LocalDataName", result);
	}

	@Test
	public void testLocalData3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalData3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("LocalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalData3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA32_16: [0001:00000010], Type: DummyMsType, LocalDataName", result);
	}

	@Test
	public void testLocalData32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalData32StMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putByteLengthPrefixedUtf8String("LocalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalData32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA32_ST: [0001:00000010], Type: DummyMsType, LocalDataName", result);
	}

	@Test
	public void testLocalData32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalData32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putNullTerminatedUtf8String("LocalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalData32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA32: [0001:00000010], Type: DummyMsType, LocalDataName", result);
	}

	@Test
	public void testGlobalData16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalData16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("GlobalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalData16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA16: [0001:00000010], Type: DummyMsType, GlobalDataName", result);
	}

	@Test
	public void testGlobalData3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalData3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("GlobalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalData3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA32_16: [0001:00000010], Type: DummyMsType, GlobalDataName", result);
	}

	@Test
	public void testGlobalData32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalData32StMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putByteLengthPrefixedUtf8String("GlobalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalData32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA32_ST: [0001:00000010], Type: DummyMsType, GlobalDataName", result);
	}

	@Test
	public void testGlobalData32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalData32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putNullTerminatedUtf8String("GlobalDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalData32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA32: [0001:00000010], Type: DummyMsType, GlobalDataName", result);
	}

	@Test
	public void testPublic16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Public16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("PublicName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Public16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PUBSYM16: [0001:00000010], Type: DummyMsType, PublicName", result);
	}

	@Test
	public void testPublic3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Public3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("PublicName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Public3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PUBSYM32_16: [0001:00000010], Type: DummyMsType, PublicName", result);
	}

	@Test
	public void testPublic32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Public32StMsSymbol.PDB_ID);
		writer.putInt(0x0f); // Public symbol flags
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putByteLengthPrefixedUtf8String("PublicName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Public32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PUBSYM32_ST: [0001:00000010], Flags: 0000000f, PublicName", result);
	}

	@Test
	public void testPublic32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Public32MsSymbol.PDB_ID);
		writer.putInt(0x0f); // Public symbol flags
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putNullTerminatedUtf8String("PublicName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Public32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PUBSYM32: [0001:00000010], Flags: 0000000f, PublicName", result);
	}

	@Test
	public void testLocalManagedDataStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalManagedDataStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putByteLengthPrefixedString("LocalManagedDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalManagedDataStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LMANDATA32_ST: [0001:00000010], Token: 00001000, LocalManagedDataName",
			result);
	}

	@Test
	public void testLocalManagedDataMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalManagedDataMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putNullTerminatedUtf8String("LocalManagedDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalManagedDataMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LMANDATA32: [0001:00000010], Token: 00001000, LocalManagedDataName", result);
	}

	@Test
	public void testGlobalManagedDataStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalManagedDataStMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putByteLengthPrefixedString("GlobalManagedDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalManagedDataStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GMANDATA32_ST: [0001:00000010], Token: 00001000, GlobalManagedDataName",
			result);
	}

	@Test
	public void testGlobalManagedDataMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalManagedDataMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset of symbol.
		writer.putUnsignedShort(0x01); // Segment.
		writer.putNullTerminatedUtf8String("GlobalManagedDataName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalManagedDataMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GMANDATA32: [0001:00000010], Token: 00001000, GlobalManagedDataName", result);
	}

	@Test
	public void testLocalThreadStorage3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalThreadStorage3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("LocalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalThreadStorage3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LTHREAD32_16: [0001:00000010], Type: DummyMsType, LocalThreadStorageName",
			result);
	}

	@Test
	public void testLocalThreadStorage32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalThreadStorage32StMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putByteLengthPrefixedUtf8String("LocalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalThreadStorage32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LTHREAD32_ST: [0001:00000010], Type: DummyMsType, LocalThreadStorageName",
			result);
	}

	@Test
	public void testLocalThreadStorage32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalThreadStorage32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putNullTerminatedUtf8String("LocalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalThreadStorage32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LTHREAD32: [0001:00000010], Type: DummyMsType, LocalThreadStorageName",
			result);
	}

	@Test
	public void testGlobalThreadStorage3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalThreadStorage3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("GlobalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalThreadStorage3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GTHREAD32_16: [0001:00000010], Type: DummyMsType, GlobalThreadStorageName",
			result);
	}

	@Test
	public void testGlobalThreadStorage32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalThreadStorage32StMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putByteLengthPrefixedUtf8String("GlobalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalThreadStorage32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GTHREAD32_ST: [0001:00000010], Type: DummyMsType, GlobalThreadStorageName",
			result);
	}

	@Test
	public void testGlobalThreadStorage32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalThreadStorage32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x10); // Offset into thread storage
		writer.putUnsignedShort(0x01); // Segment of thread storage.
		writer.putNullTerminatedUtf8String("GlobalThreadStorageName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalThreadStorage32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GTHREAD32: [0001:00000010], Type: DummyMsType, GlobalThreadStorageName",
			result);
	}

	@Test
	public void testLocalDataHLSLMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalDataHLSLMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putUnsignedShort(0x02); // Base data slot
		writer.putUnsignedShort(0x03); // Base data byte offset start
		writer.putUnsignedShort(0x04); // Texture slot start
		writer.putUnsignedShort(0x05); // Sampler slot start
		writer.putUnsignedShort(0x06); // UAV slot start
		writer.putNullTerminatedUtf8String("LocalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalDataHLSLMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA_HLSL: Type: DummyMsType. INPUT\n" +
			"   base data: slot = 2 offset = 3, texture slot = 4, sampler slot = 5," +
			" UAV slot = 6", result);
	}

	@Test
	public void testLocalDataHLSL32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalDataHLSL32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x02); // Base data slot
		writer.putUnsignedInt(0x03); // Base data byte offset start
		writer.putUnsignedInt(0x04); // Texture slot start
		writer.putUnsignedInt(0x05); // Sampler slot start
		writer.putUnsignedInt(0x06); // UAV slot start
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putNullTerminatedUtf8String("LocalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalDataHLSL32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA_HLSL32: Type: DummyMsType. INPUT\n" +
			"   base data: slot = 2 offset = 3, texture slot = 4, sampler slot = 5," +
			" UAV slot = 6", result);
	}

	@Test
	public void testLocalDataHLSL32ExtMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalDataHLSL32ExtMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x02); // HLSL register index (regID)
		writer.putUnsignedInt(0x03); // Base data byte offset start
		writer.putUnsignedInt(0x04); // bindSpace (binding space)
		writer.putUnsignedInt(0x05); // bindSlot (lower bound in binding space)
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putNullTerminatedUtf8String("LocalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalDataHLSL32ExtMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LDATA_HLSL32_EX: Type: DummyMsType. INPUT\n" +
			"   register index = 2, base data offset start = 3, bind space = 4," + " bind slot = 5",
			result);
	}

	@Test
	public void testGlobalDataHLSLMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalDataHLSLMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putUnsignedShort(0x02); // Base data slot
		writer.putUnsignedShort(0x03); // Base data byte offset start
		writer.putUnsignedShort(0x04); // Texture slot start
		writer.putUnsignedShort(0x05); // Sampler slot start
		writer.putUnsignedShort(0x06); // UAV slot start
		writer.putNullTerminatedUtf8String("GlobalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalDataHLSLMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA_HLSL: Type: DummyMsType. INPUT\n" +
			"   base data: slot = 2 offset = 3, texture slot = 4, sampler slot = 5," +
			" UAV slot = 6", result);
	}

	@Test
	public void testGlobalDataHLSL32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalDataHLSL32MsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x02); // Base data slot
		writer.putUnsignedInt(0x03); // Base data byte offset start
		writer.putUnsignedInt(0x04); // Texture slot start
		writer.putUnsignedInt(0x05); // Sampler slot start
		writer.putUnsignedInt(0x06); // UAV slot start
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putNullTerminatedUtf8String("GlobalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalDataHLSL32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA_HLSL32: Type: DummyMsType. INPUT\n" +
			"   base data: slot = 2 offset = 3, texture slot = 4, sampler slot = 5," +
			" UAV slot = 6", result);
	}

	@Test
	public void testGlobalDataHLSL32ExtMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalDataHLSL32ExtMsSymbol.PDB_ID);
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x02); // HLSL register index (regID)
		writer.putUnsignedInt(0x03); // Base data byte offset start
		writer.putUnsignedInt(0x04); // bindSpace (binding space)
		writer.putUnsignedInt(0x05); // bindSlot (lower bound in binding space)
		writer.putUnsignedShort(0x01); // HLSL register type
		writer.putNullTerminatedUtf8String("GlobalDataHighLevelShaderLanguageSymbolName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalDataHLSL32ExtMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GDATA_HLSL32_EX: Type: DummyMsType. INPUT\n" +
			"   register index = 2, base data offset start = 3, bind space = 4," + " bind slot = 5",
			result);
	}

	@Test
	public void testLocalProcedureStart16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStart16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedShort(0x100); // Procedure length
		writer.putUnsignedShort(0x10); // Debug start offset
		writer.putUnsignedShort(0x20); // Debug end offset
		writer.putUnsignedShort(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStart16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedureStart3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStart3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStart3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32_16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedureStart32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStart32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStart32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedureStart32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStart32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStart32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testGlobalProcedureStart16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStart16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedShort(0x100); // Procedure length
		writer.putUnsignedShort(0x10); // Debug start offset
		writer.putUnsignedShort(0x20); // Debug end offset
		writer.putUnsignedShort(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStart16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROC16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testGlobalProcedureStart3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStart3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStart3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROC32_16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testGlobalProcedureStart32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStart32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStart32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROC32_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testGlobalProcedureStart32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStart32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("GlobalProcedureStartName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStart32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROC32: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedure32IdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedure32IdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedure32IdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedure32IdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			" LocalProcedure32IdName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testGlobalProcedure32IdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedure32IdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("GlobalProcedure32IdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedure32IdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROC32_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			" GlobalProcedure32IdName\n" + "   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedureStart32DeferredProcedureCallMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStart32DeferredProcedureCallMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedureStart32DeferredProcedureCallName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStart32DeferredProcedureCallMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32_DPC: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStart32DeferredProcedureCallName\n" + "   Parent: 00000010," +
			" End: 00000010, Next: 00000010\n" + "   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedure32DeferredProcedureCallIdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedure32DeferredProcedureCallIdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedure32DeferredProcedureCallIdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedure32DeferredProcedureCallIdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROC32_DPC_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			" LocalProcedure32DeferredProcedureCallIdName\n" + "   Parent: 00000010," +
			" End: 00000010, Next: 00000010\n" + "   Debug start: 00000010, Debug end: 00000020\n" +
			"Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info", result);
	}

	@Test
	public void testLocalProcedureStartMips16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStartMips16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStartMips16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCMIPSSYM_16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testLocalProcedureStartMipsStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStartMipsStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStartMipsStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCMIPSSYM_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testLocalProcedureStartMipsMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStartMipsMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putNullTerminatedUtf8String("LocalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStartMipsMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCMIPSSYM: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testGlobalProcedureStartMips16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStartMips16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // Type index
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStartMips16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCMIPSSYM_16: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testGlobalProcedureStartMipsStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStartMipsStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStartMipsStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCMIPSSYM_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testGlobalProcedureStartMipsMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStartMipsMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putNullTerminatedUtf8String("GlobalProcedureStartMipsName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStartMipsMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCMIPSSYM: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testLocalProcedureMipsIdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureMipsIdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putNullTerminatedUtf8String("LocalProcedureMipsIdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureMipsIdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCMIPSSYM_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testGlobalProcedureMipsIdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureMipsIdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x55); // integer register save mask
		writer.putUnsignedInt(0xaa); // floating point register save mask
		writer.putUnsignedInt(0x50); // integer register save offset
		writer.putUnsignedInt(0xa0); // floating point register offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedByte(0x01); // Return value register
		writer.putUnsignedByte(0x01); // Frame pointer register
		writer.putNullTerminatedUtf8String("GlobalProcedureMipsIdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureMipsIdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCMIPSSYM_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			"    Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Reg Save: 00000055, FP Save: 000000AA, Int Offset: 00000050," +
			" FP Offset: 000000A0\n" + "   Return Reg: al, Frame Reg: al", result);
	}

	@Test
	public void testLocalProcedureStartIa64StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStartIa64StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LocalProcedureStartIa64Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStartIa64StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCIA64_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartIa64Name   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testLocalProcedureStartIa64MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureStartIa64MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedureStartIa64Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureStartIa64MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCIA64: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" LocalProcedureStartIa64Name   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testGlobalProcedureStartIa64StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStartIa64StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("GlobalProcedureStartIa64Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStartIa64StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCIA64_ST: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartIa64Name   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testGlobalProcedureStartIa64MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureStartIa64MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("GlobalProcedureStartIa64Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureStartIa64MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCIA64: [0001:00000030], Length: 00000100, Type: DummyMsType," +
			" GlobalProcedureStartIa64Name   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testLocalProcedureIa64IdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureIa64IdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LocalProcedureIa64IdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureIa64IdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCIA64_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			" LocalProcedureIa64IdName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testGlobalProcedureIa64IdMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalProcedureIa64IdMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putInt(4096); // Type index
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x01); // Return value register
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("GlobalProcedureIa64IdName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalProcedureIa64IdMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GPROCIA64_ID: [0001:00000030], Length: 00000100, ID: DummyMsType," +
			" GlobalProcedureIa64IdName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testThunk16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Thunk16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedShort(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(1); // Length of thunk
		writer.putUnsignedByte(0x01); // Type of thunk (1=ADJUSTOR)
		writer.putByteLengthPrefixedUtf8String("ThunkName");
		//variant info (for ADJUSTOR)
		writer.putUnsignedShort(0x02); // unsigned short (variant)
		writer.putByteLengthPrefixedUtf8String("VariantString");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Thunk16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("THUNK16: [0001:00000030], Length: 00000001, ThunkName\n" +
			"   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Type: Adjustor, Delta: 2, Target: VariantString", result);
	}

	@Test
	public void testThunkStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Thunk32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(1); // Length of thunk
		writer.putUnsignedByte(0x01); // Type of thunk (1=ADJUSTOR)
		writer.putByteLengthPrefixedUtf8String("ThunkName");
		//variant info (for ADJUSTOR)
		writer.putUnsignedShort(0x02); // unsigned short (variant)
		writer.putByteLengthPrefixedUtf8String("VariantString");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Thunk32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("THUNK32_ST: [0001:00000030], Length: 00000001, ThunkName\n" +
			"   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Type: Adjustor, Delta: 2, Target: VariantString", result);
	}

	@Test
	public void testThunkMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Thunk32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(1); // Length of thunk
		writer.putUnsignedByte(0x01); // Type of thunk (1=ADJUSTOR)
		writer.putNullTerminatedUtf8String("ThunkName");
		//variant info (for ADJUSTOR)
		writer.putUnsignedShort(0x02); // unsigned short (variant)
		writer.putNullTerminatedUtf8String("VariantString");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Thunk32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("THUNK32: [0001:00000030], Length: 00000001, ThunkName\n" +
			"   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Type: Adjustor, Delta: 2, Target: VariantString", result);
	}

	@Test
	public void testBlock16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Block16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedShort(0x10); // Block length
		writer.putUnsignedShort(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putByteLengthPrefixedUtf8String("BlockName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Block16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BLOCK16: [0001:00000030], Length: 00000010, BlockName\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testBlock32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Block32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // Block length
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putByteLengthPrefixedUtf8String("BlockName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Block32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BLOCK32_ST: [0001:00000030], Length: 00000010, BlockName\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testBlock32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Block32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // Block length
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putNullTerminatedUtf8String("BlockName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Block32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BLOCK32: [0001:00000030], Length: 00000010, BlockName\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testWith16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(With16MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedShort(0x10); // Block length
		writer.putUnsignedShort(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putByteLengthPrefixedUtf8String("WithExpression");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof With16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("WITH16: [0001:00000030], Length: 00000010, WithExpression\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testWith32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(With32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // Block length
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putByteLengthPrefixedUtf8String("WithExpression");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof With32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("WITH32_ST: [0001:00000030], Length: 00000010, WithExpression\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testWith32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(With32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // Block length
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putNullTerminatedUtf8String("WithExpression");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof With32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("WITH32: [0001:00000030], Length: 00000010, WithExpression\n" +
			"   Parent: 00000010, End: 00000010", result);
	}

	@Test
	public void testLabel16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Label16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LabelName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Label16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LABEL16: [0001:00000030], LabelName Flags: Frame Ptr Present, Interrupt," +
			" FAR, Never Return, Not Reached, Custom Calling Convention, Do Not Inline," +
			" Optimized Debug Info", result);
	}

	@Test
	public void testLabel32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Label32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putByteLengthPrefixedUtf8String("LabelName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Label32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LABEL32_ST: [0001:00000030], LabelName Flags: Frame Ptr Present, Interrupt," +
			" FAR, Never Return, Not Reached, Custom Calling Convention, Do Not Inline," +
			" Optimized Debug Info", result);
	}

	@Test
	public void testLabel32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Label32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putNullTerminatedUtf8String("LabelName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Label32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LABEL32: [0001:00000030], LabelName Flags: Frame Ptr Present, Interrupt," +
			" FAR, Never Return, Not Reached, Custom Calling Convention, Do Not Inline," +
			" Optimized Debug Info", result);
	}

	@Test
	public void testChangeExecutionModel16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ChangeExecutionModel16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x40); // Execution model (0x40=PCODE)
		writer.putUnsignedShort(0x10); // pcode: offset to pcode function table
		writer.putUnsignedShort(0x20); // pcode: offset to segment pcode information
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ChangeExecutionModel16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CEXMODEL16:\n" + "   segment, offset = 0001:00000030, model = PCODE\n" +
			"offsetToPcodeFunctionTable = 00000010," +
			" offsetToSegmentPcodeInformation = 00000020", result);
	}

	@Test
	public void testChangeExecutionModel32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ChangeExecutionModel32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // Offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(0x40); // Execution model (0x40=PCODE)
		writer.putUnsignedInt(0x10); // pcode: offset to pcode function table
		writer.putUnsignedInt(0x20); // pcode: offset to segment pcode information
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ChangeExecutionModel32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CEXMODEL32:\n" + "   segment, offset = 0001:00000030, model = PCODE\n" +
			"offsetToPcodeFunctionTable = 00000010," +
			" offsetToSegmentPcodeInformation = 00000020", result);
	}

	@Test
	public void testVirtualFunctionTable16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTable16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x10); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // root
		writer.putUnsignedShort(4096); // path
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof VirtualFunctionTable16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("VFTABLE16: [0001:00000010], DummyMsType:DummyMsType", result);
	}

	@Test
	public void testVirtualFunctionTable3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTable3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		writer.putUnsignedShort(4096); // root
		writer.putUnsignedShort(4096); // path
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof VirtualFunctionTable3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("VFTABLE32_16: [0001:00000010], DummyMsType:DummyMsType", result);
	}

	@Test
	public void testVirtualFunctionTable32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTable32MsSymbol.PDB_ID);
		writer.putUnsignedInt(4096); // root
		writer.putUnsignedInt(4096); // path
		writer.putUnsignedInt(0x10); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof VirtualFunctionTable32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("VFTABLE32: [0001:00000010], DummyMsType:DummyMsType", result);
	}

	@Test
	public void testRegisterRelativeAddress16MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterRelativeAddress16MsSymbol.PDB_ID);
		writer.putUnsignedShort(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Register index
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("RegisterRelativeAddressName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterRelativeAddress16MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGREL16: al+00000030, Type: DummyMsType, RegisterRelativeAddressName",
			result);
	}

	@Test
	public void testRegisterRelativeAddress3216MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterRelativeAddress3216MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putUnsignedShort(1); // Register index
		writer.putUnsignedShort(4096); // Type index
		writer.putByteLengthPrefixedUtf8String("RegisterRelativeAddressName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterRelativeAddress3216MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGREL32_16: al+00000030, Type: DummyMsType, RegisterRelativeAddressName",
			result);
	}

	@Test
	public void testRegisterRelativeAddress32StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterRelativeAddress32StMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putInt(4096); // Type index
		writer.putUnsignedShort(1); // Register index
		writer.putByteLengthPrefixedUtf8String("RegisterRelativeAddressName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterRelativeAddress32StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGREL32_ST: al+00000030, Type: DummyMsType, RegisterRelativeAddressName",
			result);
	}

	@Test
	public void testRegisterRelativeAddress32MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(RegisterRelativeAddress32MsSymbol.PDB_ID);
		writer.putUnsignedInt(0x30); // offset of symbol
		writer.putInt(4096); // Type index
		writer.putUnsignedShort(1); // Register index
		writer.putNullTerminatedUtf8String("RegisterRelativeAddressName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof RegisterRelativeAddress32MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REGREL32: al+00000030, Type: DummyMsType, RegisterRelativeAddressName",
			result);
	}

	@Test
	public void testStaticLinkForMipsExceptionHandlingMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StaticLinkForMipsExceptionHandlingMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // Register
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof StaticLinkForMipsExceptionHandlingMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("SLINK32: framesize = 00000010, offset = 00000020, register = al", result);
	}

	@Test
	public void testProcedureReferenceStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ProcedureReferenceStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putAlign(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ProcedureReferenceStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PROCREF_ST: 00000010: (   1, 00000020)", result);
	}

	@Test
	public void testDataReferenceStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DataReferenceStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putAlign(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DataReferenceStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DATAREF_ST: 00000010: (   1, 00000020)", result);
	}

	@Test
	public void testLocalProcedureReferenceStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureReferenceStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putAlign(0);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureReferenceStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCREF_ST: 00000010: (   1, 00000020)", result);
	}

	@Test
	public void testProcedureReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ProcedureReferenceMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putNullTerminatedUtf8String("ProcedureReferenceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ProcedureReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PROCREF: 00000010: (   1, 00000020) ProcedureReferenceName", result);
	}

	@Test
	public void testDataReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DataReferenceMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putNullTerminatedUtf8String("DataReferenceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DataReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DATAREF: 00000010: (   1, 00000020) DataReferenceName", result);
	}

	@Test
	public void testLocalProcedureReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalProcedureReferenceMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putNullTerminatedUtf8String("LocalProcedureReferenceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalProcedureReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LPROCREF: 00000010: (   1, 00000020) LocalProcedureReferenceName", result);
	}

	@Test
	public void testAnnotationReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AnnotationReferenceMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putNullTerminatedUtf8String("AnnotationReferenceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AnnotationReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ANNOTATIONREF: 00000010: (   1, 00000020) AnnotationReferenceName", result);
	}

	@Test
	public void testTokenReferenceToManagedProcedureMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(TokenReferenceToManagedProcedureMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // frame size of parent procedure
		writer.putUnsignedInt(0x20); // offset of symbol
		writer.putUnsignedShort(1); // module containing the symbol
		writer.putNullTerminatedUtf8String("TokenReferenceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof TokenReferenceToManagedProcedureMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("TOKENREF: 00000010: (   1, 00000020) TokenReferenceName", result);
	}

	@Test
	public void testAlignMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AlignMsSymbol.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // Putting data, but might never be any.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AlignMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("Align Record, Length = 0x2", result);
	}

	@Test
	public void testOemDefinedMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OemDefinedMsSymbol.PDB_ID);
		// SS_OEMID GUID (from API doc)
		writer.putUnsignedInt(0xc6ea3fc9);
		writer.putUnsignedShort(0x59b3);
		writer.putUnsignedShort(0x49d6);
		writer.putBytes(new byte[] { (byte) 0xbc, 0x25, 0x09, 0x02, (byte) 0xbb, (byte) 0xab,
			(byte) 0xb4, 0x60 });
		writer.putInt(4096); // Type index
		writer.putBytes(new byte[] { 0x01, 0x02, 0x03, 0x04 }); // User data, with align 4
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof OemDefinedMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"OEM: c6ea3fc9-59b3-49d6-bc25-0902bbabb460, Type DummyMsType\n" + "   04030201",
			result);
	}

	@Test
	public void testLocalSlotIndexFieldedLILStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalSlotIndexFieldedLILStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // slot index
		writer.putInt(4096); // type index or metadata token
		writer.putByteLengthPrefixedUtf8String("LocalSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalSlotIndexFieldedLILStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LOCALSLOT_ST: [00000010], Type: DummyMsType, LocalSlotName", result);
	}

	@Test
	public void testLocalSlotIndexFieldedLILMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalSlotIndexFieldedLILMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // slot index
		writer.putInt(4096); // type index or metadata token
		writer.putNullTerminatedUtf8String("LocalSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalSlotIndexFieldedLILMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LOCALSLOT: [00000010], Type: DummyMsType, LocalSlotName", result);
	}

	@Test
	public void testParameterSlotIndexFieldedLILStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ParameterSlotIndexFieldedLILStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // slot index
		writer.putInt(4096); // type index or metadata token
		writer.putByteLengthPrefixedUtf8String("ParamSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ParameterSlotIndexFieldedLILStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PARAMSLOT_ST: [00000010], Type: DummyMsType, ParamSlotName", result);
	}

	@Test
	public void testParameterSlotIndexFieldedLILMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ParameterSlotIndexFieldedLILMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // slot index
		writer.putInt(4096); // type index or metadata token
		writer.putNullTerminatedUtf8String("ParamSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ParameterSlotIndexFieldedLILMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PARAMSLOT: [00000010], Type: DummyMsType, ParamSlotName", result);
	}

	@Test
	public void testAnnotationMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AnnotationMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Offset
		writer.putUnsignedShort(1); // Segment
		writer.putUnsignedShort(3); // Count of annotation strings
		writer.putNullTerminatedUtf8String("Annotation0Name");
		writer.putNullTerminatedUtf8String("Annotation1Name");
		writer.putNullTerminatedUtf8String("Annotation2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AnnotationMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ANNOTATION: [0001:00003000]\n" + "    0: Annotation0Name\n" +
			"    1: Annotation1Name\n" + "    2: Annotation2Name", result);
	}

	@Test
	public void testReserved1MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Reserved1MsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Reserved1MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("RESERVED1", result);
	}

	@Test
	public void testReserved2MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Reserved2MsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Reserved2MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("RESERVED2", result);
	}

	@Test
	public void testReserved3MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Reserved3MsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Reserved3MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("RESERVED3", result);
	}

	@Test
	public void testReserved4MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Reserved4MsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof Reserved4MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("RESERVED4", result);
	}

	@Test
	public void testLocalManagedProcedureStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalManagedProcedureStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x10000); // Token
		writer.putUnsignedInt(0x3000); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putUnsignedShort(0x01); // Return register
		writer.putByteLengthPrefixedUtf8String("LocalManagedProcedureName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalManagedProcedureStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LMANPROC_ST: [0001:00003000], Length: 00000100, Token: 65536," +
			" LocalManagedProcedureName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testLocalManagedProcedureMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalManagedProcedureMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x10000); // Token
		writer.putUnsignedInt(0x3000); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putUnsignedShort(0x01); // Return register
		writer.putNullTerminatedUtf8String("LocalManagedProcedureName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalManagedProcedureMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LMANPROC: [0001:00003000], Length: 00000100, Token: 65536," +
			" LocalManagedProcedureName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testGlobalManagedProcedureStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalManagedProcedureStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x10000); // Token
		writer.putUnsignedInt(0x3000); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putUnsignedShort(0x01); // Return register
		writer.putByteLengthPrefixedUtf8String("GlobalManagedProcedureName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalManagedProcedureStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GMANPROC_ST: [0001:00003000], Length: 00000100, Token: 65536," +
			" GlobalManagedProcedureName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testGlobalManagedProcedureMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(GlobalManagedProcedureMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x10); // pointer to next symbol
		writer.putUnsignedInt(0x100); // Procedure length
		writer.putUnsignedInt(0x10); // Debug start offset
		writer.putUnsignedInt(0x20); // Debug end offset
		writer.putUnsignedInt(0x10000); // Token
		writer.putUnsignedInt(0x3000); // offset of symbol
		writer.putUnsignedShort(1); // Segment of symbol
		byte[] procflags =
			createProcedureMsFlagsBuffer(true, true, true, true, true, true, true, true);
		writer.putBytes(procflags);
		writer.putUnsignedShort(0x01); // Return register
		writer.putNullTerminatedUtf8String("GlobalManagedProcedureName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof GlobalManagedProcedureMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("GMANPROC: [0001:00003000], Length: 00000100, Token: 65536," +
			" GlobalManagedProcedureName   Parent: 00000010, End: 00000010, Next: 00000010\n" +
			"   Debug start: 00000010, Debug end: 00000020\n" +
			"   Flags: Frame Ptr Present, Interrupt, FAR, Never Return, Not Reached," +
			" Custom Calling Convention, Do Not Inline, Optimized Debug Info\n" +
			"   Return Reg: al", result);
	}

	@Test
	public void testManLocOrParamReltoVFPStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManLocOrParamReltoVFPStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putByteLengthPrefixedUtf8String("ManagedFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManLocOrParamReltoVFPStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANFRAMEREL_ST: [00003000], [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedFrameName", result);
	}

	@Test
	public void testManLocOrParamReltoVFPMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManLocOrParamReltoVFPMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putNullTerminatedUtf8String("ManagedFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManLocOrParamReltoVFPMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANFRAMEREL: [00003000], [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedFrameName", result);
	}

	@Test
	public void testAttribLocOrParamReltoVFPMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AttribLocOrParamReltoVFPMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putNullTerminatedUtf8String("AttributedFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AttribLocOrParamReltoVFPMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ATTR_MANFRAMEREL: [00003000], [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static AttributedFrameName", result);
	}

	@Test
	public void testManagedLocalOrParameterSIRStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIRStMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(1); // Register
		writer.putByteLengthPrefixedUtf8String("ManagedRegisterName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIRStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANREGISTER_ST: al, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedRegisterName", result);
	}

	@Test
	public void testManagedLocalOrParameterSIRMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIRMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(1); // Register
		writer.putNullTerminatedUtf8String("ManagedRegisterName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIRMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANREGISTER: al, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedRegisterName", result);
	}

	@Test
	public void testAttributedLocalOrParameterSIRMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AttributedLocalOrParameterSIRMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(1); // Register
		writer.putNullTerminatedUtf8String("AttributedRegisterName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AttributedLocalOrParameterSIRMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ATTR_REGISTER: al, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static AttributedRegisterName", result);
	}

	@Test
	public void testManagedSymbolWithSlotIndexFieldStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedSymbolWithSlotIndexFieldStMsSymbol.PDB_ID);
		writer.putUnsignedInt(1); // Slot index
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putByteLengthPrefixedUtf8String("ManagedSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedSymbolWithSlotIndexFieldStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANSLOT_ST: 1, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedSlotName", result);
	}

	@Test
	public void testManagedSymbolWithSlotIndexFieldMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedSymbolWithSlotIndexFieldMsSymbol.PDB_ID);
		writer.putUnsignedInt(1); // Slot index
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putNullTerminatedUtf8String("ManagedSlotName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedSymbolWithSlotIndexFieldMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANSLOT: 1, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static ManagedSlotName", result);
	}

	@Test
	public void testManagedLocalOrParameterSIMRStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIMRStMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedByte(3); // Number of registers
		writer.putUnsignedByte(1); // Register
		writer.putUnsignedByte(2); // Register
		writer.putUnsignedByte(3); // Register
		writer.putByteLengthPrefixedUtf8String("ManagedManyRegisterName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIMRStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANMANYREG_ST: al, cl, dl DummyMsType ManagedManyRegisterName", result);
	}

	@Test
	public void testManagedLocalOrParameterSIMRMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIMRMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedByte(3); // Number of registers
		writer.putUnsignedByte(1); // Register
		writer.putUnsignedByte(2); // Register
		writer.putUnsignedByte(3); // Register
		writer.putNullTerminatedUtf8String("ManagedManyRegisterName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIMRMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANMANYREG: al, cl, dl DummyMsType ManagedManyRegisterName", result);
	}

	@Test
	public void testManagedLocalOrParameterSIMR2StMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIMR2StMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(3); // Number of registers
		writer.putUnsignedShort(1); // Register
		writer.putUnsignedShort(2); // Register
		writer.putUnsignedShort(3); // Register
		writer.putByteLengthPrefixedUtf8String("ManagedManyRegister2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIMR2StMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANMANYREG2_ST: al, cl, dl DummyMsType ManagedManyRegister2Name", result);
	}

	@Test
	public void testManagedLocalOrParameterSIMR2MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedLocalOrParameterSIMR2MsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(3); // Number of registers
		writer.putUnsignedShort(1); // Register
		writer.putUnsignedShort(2); // Register
		writer.putUnsignedShort(3); // Register
		writer.putNullTerminatedUtf8String("ManagedManyRegister2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManagedLocalOrParameterSIMR2MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANMANYREG2: al, cl, dl DummyMsType ManagedManyRegister2Name", result);
	}

	@Test
	public void testAttributedLocalOrParameterSIMRMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AttributedLocalOrParameterSIMRMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(3); // Number of registers
		writer.putUnsignedShort(1); // Register
		writer.putUnsignedShort(2); // Register
		writer.putUnsignedShort(3); // Register
		writer.putNullTerminatedUtf8String("ManagedManyRegister2Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AttributedLocalOrParameterSIMRMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ATTR_MANYREG: al, cl, dl DummyMsType ManagedManyRegister2Name", result);
	}

	@Test
	public void testManLocOrParamReltoAMPStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManLocOrParamReltoAMPStMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		writer.putUnsignedShort(1); // Register index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putByteLengthPrefixedUtf8String("ManagedAltFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManLocOrParamReltoAMPStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANREGREL_ST: al+00003000, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static, ManagedAltFrameName", result);
	}

	@Test
	public void testManLocOrParamReltoAMPMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManLocOrParamReltoAMPMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		writer.putUnsignedShort(1); // Register index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putNullTerminatedUtf8String("ManagedAltFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ManLocOrParamReltoAMPMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANREGREL: al+00003000, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static, ManagedAltFrameName", result);
	}

	@Test
	public void testAttribLocOrParamReltoAMPMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AttribLocOrParamReltoAMPMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x3000); // Frame-relative offset
		writer.putInt(4096); // type index or mdatadata token
		writer.putUnsignedShort(1); // Register index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		byte[] attributesBuffer = createLocalVariableAttributesBuffer(0x1000, 1, localVarFlags);
		writer.putBytes(attributesBuffer);
		writer.putNullTerminatedUtf8String("AttributedAltFrameName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof AttribLocOrParamReltoAMPMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ATTR_REGREL: al+00003000, [0001:00001000]: Param: 4096 Address Taken," +
			" Compiler Generated, aggregate, aggregated, aliased, alias, return value," +
			" optimized away, file static, AttributedAltFrameName", result);
	}

	@Test
	public void testIndexForTypeReferencedByNameFromMetadataMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(IndexForTypeReferencedByNameFromMetadataMsSymbol.PDB_ID);
		writer.putInt(4096); // type index or mdatadata token
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof IndexForTypeReferencedByNameFromMetadataMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MANTYPEREF: DummyMsType", result);
	}

	@Test
	public void testUsingNamespaceStMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UsingNamespaceStMsSymbol.PDB_ID);
		writer.putByteLengthPrefixedUtf8String("UsingNamespaceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UsingNamespaceStMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNAMESPACE_ST: UsingNamespaceName", result);
	}

	@Test
	public void testUsingNamespaceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UsingNamespaceMsSymbol.PDB_ID);
		writer.putNullTerminatedUtf8String("UsingNamespaceName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UsingNamespaceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNAMESPACE: UsingNamespaceName", result);
	}

	@Test
	public void testTrampolineMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(TrampolineMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // trampoline subtype
		writer.putUnsignedShort(0x10); // size of thunk
		writer.putUnsignedInt(0x1000); // thunk offset
		writer.putUnsignedInt(0x2000); // thunk target offset
		writer.putUnsignedShort(1); // section index of thunk
		writer.putUnsignedShort(1); // section index of thunk target
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof TrampolineMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"TRAMPOLINE: subtype BranchIsland, code size = 16 bytes\n" +
				"   Thunk address: [0001:00001000]\n" + "   Thunk target:  [0001:00002000]",
			result);
	}

	@Test
	public void testSeparatedCodeFromCompilerSupportMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SeparatedCodeFromCompilerSupportMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // pointer to the parent
		writer.putUnsignedInt(0x10); // pointer to this block's end
		writer.putUnsignedInt(0x100); // count of bytes in block
		writer.putUnsignedInt(0x03); // flags
		writer.putUnsignedInt(0x1000); // Offset of separated code
		writer.putUnsignedInt(0x1000); // Offset of parent of enclosing scope
		writer.putUnsignedShort(1); // Section of separated code
		writer.putUnsignedShort(1); // Section of parent of enclosing scope
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof SeparatedCodeFromCompilerSupportMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"SEPCODE: [0001:00001000], Length: 00000100, Parent: 00000010, End: 00000010\n" +
				"   Parent scope beings: [0001:00001000]\n" +
				"   Separated code flags: lexscope retparent",
			result);
	}

	@Test
	public void testLocalSymbolInOptimizedCode2005MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalSymbolInOptimizedCode2005MsSymbol.PDB_ID);
		writer.putInt(4096); // type index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		writer.putBytes(localVarFlags);
		writer.putNullTerminatedUtf8String("LocalSymbolInOptimizedCode2005Name");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalSymbolInOptimizedCode2005MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LOCAL_2005: Param: 00001000  Address Taken, Compiler Generated, aggregate," +
			" aggregated, aliased, alias, return value, optimized away, file static," +
			" LocalSymbolInOptimizedCode2005Name", result);
	}

	@Test
	public void testLocalSymbolInOptimizedCodeMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalSymbolInOptimizedCodeMsSymbol.PDB_ID);
		writer.putInt(4096); // type index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		writer.putBytes(localVarFlags);
		writer.putNullTerminatedUtf8String("LocalSymbolInOptimizedCodeName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalSymbolInOptimizedCodeMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LOCAL: Param: 00001000  Address Taken, Compiler Generated, aggregate," +
			" aggregated, aliased, alias, return value, optimized away, file static," +
			" LocalSymbolInOptimizedCodeName", result);
	}

	@Test
	public void testDefinedSingleAddressRange2005MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefinedSingleAddressRange2005MsSymbol.PDB_ID);
		// API not given; writing dummy data here.
		writer.putBytes(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DefinedSingleAddressRange2005MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRAMGE_2005: <NO API DETAILS, 8 BYTES>", result);
	}

	@Test
	public void testDefinedMultipleAddressRanges2005MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefinedMultipleAddressRanges2005MsSymbol.PDB_ID);
		// API not given; writing dummy data here.
		writer.putBytes(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DefinedMultipleAddressRanges2005MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRAMGE2_2005: <NO API DETAILS, 8 BYTES>", result);
	}

	@Test
	public void testPeCoffSectionMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PeCoffSectionMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // Section number
		writer.putUnsignedByte(16); // power-of-2 alignment of this section
		writer.putUnsignedByte(0x00); // reserved (must be zero)
		writer.putUnsignedInt(0); // rva (?)
		writer.putUnsignedInt(0x100); // cb (probably length?)
		writer.putUnsignedInt(0x05); // characteristics
		writer.putNullTerminatedUtf8String("PeCoffSectionName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof PeCoffSectionMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("SECTION: [0001], RVA = 00000000, Length = 00000100, Align = 00000010," +
			" Characteristics = 00000005, PeCoffSectionName", result);
	}

	@Test
	public void testPeCoffGroupMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PeCoffGroupMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x100); // cb (probably length?)
		writer.putUnsignedInt(0x05); // characteristics
		writer.putUnsignedInt(0x1000); // Offset
		writer.putUnsignedShort(1); // Segment
		writer.putNullTerminatedUtf8String("PeCoffGroupName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof PeCoffGroupMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("COFFGROUP: [0001:00001000], Length = 00000100, Characteristics = 00000005," +
			" PeCoffGroupName", result);
	}

	@Test
	public void testExportMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ExportMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // Ordinal
		writer.putUnsignedShort(0x2f); // flags
		writer.putNullTerminatedUtf8String("ExportName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ExportMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("EXPORT: Ordinal = 1 (implicit), CONSTANT, DATA, PRIVATE, NONAME," +
			" FORWARDER, ExportName", result);
	}

	@Test
	public void testIndirectCallSiteInfoMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(IndirectCallSiteInfoMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // Offset
		writer.putUnsignedShort(1); // Section
		writer.putUnsignedShort(0x00); // Reserved (must be zero)
		writer.putUnsignedInt(4096); // type index
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof IndirectCallSiteInfoMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CALLSITEINFO: [0001:00001000], Type = DummyMsType", result);
	}

	@Test
	public void testFrameSecurityCookieMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FrameSecurityCookieMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // Offset
		writer.putUnsignedShort(1); // Register index
		// One real data example seems to indicate cookie type is only one byte (for the enum)
		writer.putUnsignedByte(0x00); // cookie type (valid values seem to be 0, 1, 2, 3)
		writer.putUnsignedByte(0x55); // flags
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof FrameSecurityCookieMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("FRAMECOOKIE: al+00001000, Type: COPY, 55", result);
	}

	@Test
	public void testDiscardedByLinkMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DiscardedByLinkMsSymbol.PDB_ID);
		writer.putUnsignedInt(1); // "discarded" enum value (0, 1, 2?)
		writer.putUnsignedInt(1); // first file ID if line number present
		writer.putUnsignedInt(234); // first line number
		// original records with invalid type indices follow.  I made up information here
		// based on what I coded in the type under test, which I admit is not correct.  Need
		// to see some real data to understand this symbol type better.
		byte[] symbolBuffer = createRegister16MsSymbolBuffer();
		writer.putUnsignedShort(symbolBuffer.length);
		writer.putBytes(symbolBuffer);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DiscardedByLinkMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DISCARDED: Not selected, FileId: 00000001, Line:      234\n" +
			"REGISTER_16: al:cl, Type: DummyMsType, registerSymbolName", result);
	}

	@Test
	public void testDefinedSingleAddressRangeMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefinedSingleAddressRangeMsSymbol.PDB_ID);
		writer.putUnsignedInt(1); // DIA program to eval value of the symbol
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DefinedSingleAddressRangeMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"DEFRANGE: DIA program NI: 0001," + "    Range: [0001:00002000] - [0001:00003000]," +
				" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)",
			result);
	}

	@Test
	public void testSubfieldDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SubfieldDARMsSymbol.PDB_ID);
		writer.putUnsignedInt(1); // DIA program to eval value of the symbol
		writer.putUnsignedInt(0x10); // Offset in parent variable
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof SubfieldDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_SUBFIELD: offset at 0010, DIA Program NI: 0001," +
			"    Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)", result);
	}

	@Test
	public void testEnregisteredSymbolDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnregisteredSymbolDARMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // register to hold value fo the symbol
		// attribute (bit 0: 1=may have no user name on one of the control flow paths
		writer.putUnsignedShort(0x01);
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EnregisteredSymbolDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_REGISTER:Attributes: MayAvailable al" +
			"   Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)", result);
	}

	@Test
	public void testFramePointerRelativeDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FramePointerRelativeDARMsSymbol.PDB_ID);
		writer.putInt(0x1000); // offset to frame pointer
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof FramePointerRelativeDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_FRAMEPOINTER_REL: FrameOffset: 1000" +
			"    Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)", result);
	}

	@Test
	public void testEnregisteredFieldOfSymbolDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnregisteredFieldOfSymbolDARMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // register holding the value of the symbol
		// attribute (bit 0: 1=may have no user name on one of the control flow paths
		writer.putUnsignedShort(0x01);
		// offset in parent variable. (12 bits; rest is padding for now)
		writer.putUnsignedInt(0x010 & 0xfff);
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EnregisteredFieldOfSymbolDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_SUBFIELD_REGISTER: offset at 0010: Attributes: MayAvailable al" +
			"   Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)", result);
	}

	@Test
	public void testFramePointerRelativeFullScopeDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FramePointerRelativeFullScopeDARMsSymbol.PDB_ID);
		writer.putInt(0x0100); // offset to frame pointer
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof FramePointerRelativeFullScopeDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: FrameOffset: 0100 FULL_SCOPE", result);
	}

	@Test
	public void testEnregisteredSymbolRelativeDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnregisteredSymbolRelativeDARMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // register holding base pointer of symbol
		// spilled member for s.i. (1 bit)
		// padding for future (3 bits)
		// offset in parent variable. (12 bits)
		writer.putUnsignedShort(0x01 | (0x10 << 4));
		writer.putInt(0x100); // offset to register (base pointer)
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof EnregisteredSymbolRelativeDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals(
			"DEFRANGE_REGISTER_REL: [al + 0100] spilledUserDefinedTypeMember offset at 16" +
				"   Range: [0001:00002000] - [0001:00003000]," +
				" 2 Gaps (startOffset, length): (0100, 80) (0400, 100)",
			result);
	}

	@Test
	public void testBuildInformationMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BuildInformationMsSymbol.PDB_ID);
		writer.putUnsignedInt(4096); // item id of build info
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof BuildInformationMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("BUILDINFO: ItemDummyMsType", result);
	}

	@Test
	public void testProcedureIdEndMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ProcedureIdEndMsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ProcedureIdEndMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PROC_ID_END", result);
	}

	@Test
	public void testInlinedFunctionCallsiteMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(InlinedFunctionCallsiteMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // pointer to the parent
		writer.putUnsignedInt(0x2000); // pointer to this block's end
		writer.putUnsignedInt(4096); // item Id of inlinee
		// Binary annotation opcode (list)
		byte[] annotationBuf1 = createInstructionAnnotationBuffer(0x01, 0x10, 0x11);
		writer.putBytes(annotationBuf1);
		byte[] annotationBuf2 = createInstructionAnnotationBuffer(0x02, 0x20, 0x21);
		writer.putBytes(annotationBuf2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof InlinedFunctionCallsiteMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("INLINESITE2: Parent: 00001000,  End: 00002000, Inlinee: ItemDummyMsType\n" +
			"  Offset 10  CodeOffsetBase 20", result);
	}

	@Test
	public void testInlinedFunctionCallsiteExtendedMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(InlinedFunctionCallsiteExtendedMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // pointer to the parent
		writer.putUnsignedInt(0x2000); // pointer to this block's end
		writer.putUnsignedInt(4096); // item Id of inlinee
		// Binary annotation opcode (list)
		writer.putUnsignedInt(2); // Number of invocations
		byte[] annotationBuf1 = createInstructionAnnotationBuffer(0x01, 0x10, 0x11);
		writer.putBytes(annotationBuf1);
		byte[] annotationBuf2 = createInstructionAnnotationBuffer(0x02, 0x20, 0x21);
		writer.putBytes(annotationBuf2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof InlinedFunctionCallsiteExtendedMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("INLINESITE2: Parent: 00001000,  End: 00002000, PGO Edge Count: 2," +
			" Inlinee: ItemDummyMsType\n" + "  Offset 10  CodeOffsetBase 20", result);
	}

	@Test
	public void testInlinedFunctionEndMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(InlinedFunctionEndMsSymbol.PDB_ID);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof InlinedFunctionEndMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("INLINESITE_END", result);
	}

	@Test
	public void testFileStaticMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FileStaticMsSymbol.PDB_ID);
		writer.putUnsignedInt(4096); // type index
		writer.putUnsignedInt(1); // index of module filename in stringtable
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		writer.putBytes(localVarFlags);
		writer.putNullTerminatedUtf8String("FileStaticName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof FileStaticMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("FILESTATIC: Param: 00001000  Address Taken, Compiler Generated, aggregate," +
			" aggregated, aliased, alias, return value, optimized away, file static," +
			" FileStaticName\n" + "   Mod: NameTableTestString", result);
	}

	@Test
	public void testLocalDeferredProcedureCallGroupSharedMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LocalDeferredProcedureCallGroupSharedMsSymbol.PDB_ID);
		writer.putUnsignedInt(4096); // type index
		byte[] localVarFlags = createLocalVariableFlagsBuffer(true, true, true, true, true, true,
			true, true, true, true, true);
		writer.putBytes(localVarFlags);
		writer.putUnsignedShort(1); // base data slot
		writer.putUnsignedShort(2); // base data offset
		writer.putNullTerminatedUtf8String("LocalDPCGroupSharedName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof LocalDeferredProcedureCallGroupSharedMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("LOCAL_DPC_GROUPSHARED: Param: 4096 Address Taken, Compiler Generated," +
			" aggregate, aggregated, aliased, alias, return value, optimized away," +
			" file static base data: slot = 1 offset = 2, LocalDPCGroupSharedName", result);
	}

	@Test
	public void testHighLevelShaderLanguageRegDimDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(HighLevelShaderLanguageRegDimDARMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // register type from HLSLREG
		int registerSpaceDimensionality = 2; // valid: 0, 1, 2.
		int spilledUdtMember = 1; // 1=true.
		int memorySpace = 1; // 4 bits
		// rest is padding.
		writer.putUnsignedShort(((memorySpace & 0x0f) << 3) | ((spilledUdtMember & 0x01) << 2) |
			(registerSpaceDimensionality & 0x03));
		writer.putUnsignedShort(0x20); // offset in parent variable.
		writer.putUnsignedShort(0x10); // size of enregistered portion
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		// Multi-dimensional offset of variable location in register.
		for (int i = 0; i < registerSpaceDimensionality; i++) {
			writer.putInt(i + 3);
		}
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof HighLevelShaderLanguageRegDimDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_HLSL: al, RegisterIndices = 2, SAMPLER" +
			"   Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100) 3 4", result);
	}

	@Test
	public void testDeferredProcedureCallPointerTagRegDimDARMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DeferredProcedureCallPointerTagRegDimDARMsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // register type from HLSLREG
		int registerSpaceDimensionality = 2; // valid: 0, 1, 2.
		int spilledUdtMember = 1; // 1=true.
		int memorySpace = 1; // 4 bits
		// rest is padding.
		writer.putUnsignedShort(((memorySpace & 0x0f) << 3) | ((spilledUdtMember & 0x01) << 2) |
			(registerSpaceDimensionality & 0x03));
		writer.putUnsignedShort(0x20); // offset in parent variable.
		writer.putUnsignedShort(0x10); // size of enregistered portion
		byte[] range = createLocalVariableAddressRangeBuffer(0x2000, 1, 0x1000);
		writer.putBytes(range);
		byte[] gap1 = createLocalVariableAddressGapBuffer(0x100, 0x80);
		writer.putBytes(gap1);
		byte[] gap2 = createLocalVariableAddressGapBuffer(0x400, 0x100);
		writer.putBytes(gap2);
		// Multi-dimensional offset of variable location in register.
		for (int i = 0; i < registerSpaceDimensionality; i++) {
			writer.putInt(i + 3);
		}
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DeferredProcedureCallPointerTagRegDimDARMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DEFRANGE_DPC_PTR_TAG: al, RegisterIndices = 2, SAMPLER" +
			"   Range: [0001:00002000] - [0001:00003000]," +
			" 2 Gaps (startOffset, length): (0100, 80) (0400, 100) 3 4", result);
	}

	@Test
	public void testDeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol.PDB_ID);
		// write array of mappings from DPC pointer tag values to symbol record offsets.
		int num = 3;
		for (int i = 0; i < num; i++) {
			writer.putUnsignedInt(i);
			writer.putUnsignedInt(0x10 * (i + 1));
		}
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof DeferredProcedureCallPointerTagToSymbolRecordMapMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("DPC_SYM_TAG_MAP: 3 entries, (0, 10), (1, 20), (2, 30)", result);
	}

	@Test
	public void testArmSwitchTableMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ArmSwitchTableMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // section-relative offset to the base for switch offsets
		writer.putUnsignedShort(1); // section index of the base
		writer.putUnsignedShort(1); // (0 - 10)
		writer.putUnsignedInt(0x2000); // section-relative offset to the table branch instruction 
		writer.putUnsignedInt(0x3000); // section-relative offset to the start of the table
		writer.putUnsignedShort(1); // section index of the table branch instruction
		writer.putUnsignedShort(1); // section index of the table
		writer.putUnsignedInt(0x5); // number of switch table entries
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ArmSwitchTableMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("ARMSWITCHTABLE:\n" + "   Base address:   [0001:00001000]\n" +
			"   Branch address: [0001:00002000]\n" + "   Table address:  [0001:00003000]\n" +
			"   Entry count = 5\n" + "   Switch entry type = unsigned byte", result);
	}

	@Test
	public void testCallersMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CallersMsSymbol.PDB_ID);
		int num = 3;
		writer.putUnsignedInt(num);
		for (int i = 0; i < num; i++) {
			writer.putUnsignedInt(4096);
		}
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CallersMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CALLERS: Count: 3\n" +
			"DummyMsType (0, args) , DummyMsType (0, args) , DummyMsType (0, args)", result);
	}

	@Test
	public void testCalleesMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(CalleesMsSymbol.PDB_ID);
		int num = 3;
		writer.putUnsignedInt(num);
		for (int i = 0; i < num; i++) {
			writer.putUnsignedInt(4096);
		}
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof CalleesMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("CALLEES: Count: 3\n" +
			"DummyMsType (0, args) , DummyMsType (0, args) , DummyMsType (0, args)", result);
	}

	@Test
	public void testProfileGuidedOptimizationDataMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ProfileGuidedOptimizationDataMsSymbol.PDB_ID);
		writer.putUnsignedInt(5); // Number of times function was called (invocations)
		BigInteger dynamicInstructionCount = new BigInteger("100");
		writer.putUnsignedLong(dynamicInstructionCount);
		writer.putUnsignedInt(15); // static instruction count
		writer.putUnsignedInt(25); // final static instruction count (after inlining)
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ProfileGuidedOptimizationDataMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("POGOINFO:\n" + "Call Count: 5\n" + "Dynamic Instruction Count: 100\n" +
			"Number of Instructions: 15\n" + "Number of Live Instructions: 25", result);
	}

	@Test
	public void testHeapAllocationSiteMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(HeapAllocationSiteMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // Offset of call site
		writer.putUnsignedShort(1); // Section of call site
		writer.putUnsignedShort(8); // Length of headp allocation call instruction
		writer.putUnsignedInt(4096); // Type index describing function signature
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof HeapAllocationSiteMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("HEAPALLOCSITE: [0001:00001000], instruction length = 8, type = DummyMsType",
			result);
	}

	@Test
	public void testModuleTypeReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ModuleTypeReferenceMsSymbol.PDB_ID);
		// flags: 1=true at given bit offset.
		//   bit 0: module does not reference a type
		//   bit 1: reference /Z7 PCH types
		//   bit 2: module contains /Z7 PCH types
		//   bit 3: module contains type info due to /Z7
		//   bit 4: module contains type info due to /Zi or /ZI
		//   bit 5: module references type info owned by other module
		//   next 9 bits are reserved
		//   next 16 bits are not specified in the API
		writer.putUnsignedInt(0x10); // flags
		// Following values have meaning depending on flags used above.
		writer.putUnsignedShort(0x01);
		writer.putUnsignedShort(0x02);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ModuleTypeReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("MODTYPEREF: /Zi TypeRef, StreamNumber=0001 (type), StreamNumber=0002 (ID)",
			result);
	}

	@Test
	public void testMiniPdbReferenceMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MiniPdbReferenceMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x10); // union of coff section and type index--context later.
		writer.putUnsignedShort(1); // module index
		// flags: 1=true at given bit offset.
		//   bit 0: reference to local (vs. global) function or data
		//   bit 1: reference to data (vs. function)
		//   bit 2: reference to User Defined Data
		//   bit 3: reference to label
		//   bit 4: reference to constant
		//   next 11 bits are reserved
		writer.putUnsignedShort(0x1f); // flags
		writer.putNullTerminatedUtf8String("MiniPdbName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof MiniPdbReferenceMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("REF_MINIPDB: (UDT) moduleIndex = 0001, TypeInformation = signed char," +
			" MiniPdbName", result);
	}

	@Test
	public void testMapToMiniPdbMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MapToMiniPdbMsSymbol.PDB_ID);
		writer.putNullTerminatedWchartString("SourcePdbFileName");
		writer.putNullTerminatedWchartString("DestinationPdbFileName");
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof MapToMiniPdbMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("PDBMAP: SourcePdbFileName -> DestinationPdbFileName", result);
	}

	@Test
	public void testExtraFrameAndProcedureInformationMsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ExtraFrameAndProcedureInformationMsSymbol.PDB_ID);
		writer.putUnsignedInt(0x1000); // total bytes in frame of procedure
		writer.putUnsignedInt(0x0030); // bytes of padding in frame
		writer.putUnsignedInt(0x0fd0); // offset from frame pointer to start of padding
		writer.putUnsignedInt(0x0100); // count of bytes of calle save registers
		writer.putUnsignedInt(0x1100); // offset of exception handler
		writer.putUnsignedShort(1); // section ID of exception handler
		// flags: 1=true at given bit offset.
		//   bit  0: function uses _alloca()
		//   bit  1: function uses setjmp()
		//   bit  2: function uses longjmp()
		//   bit  3: function uses inline asm
		//   bit  4: function has EH states
		//   bit  5: function was specified as inline
		//   bit  6: function has SEH
		//   bit  7: function is __declspec(naked)
		//   bit  8: function has buffer security check introduced by /GS
		//   bit  9: function compiled with /EHa
		//   bit 10: function has /GS buffer checks, but stack ordering could not be done
		//   bit 11: function was inline within another function
		//   bit 12: function is __declspec(strict_gs_check)
		//   bit 13: function is __declspec(safebuffers)
		//   bits 14-15: record function's local pointer explicitly
		//   bits 16-17: record function's parameter pointer explicitly
		//   bit  18: function was compiled with PGO/PGU
		//   bit  19: function Do we have valid Pogo counts?
		//   bit  20: function Did we optimized for speed?
		//   bit  21: function contains CFG checks (and no write checks)
		//   bit  22: function contains CFW check and/or instrumentation
		//   next 9 bits are reserved
		writer.putUnsignedInt(0x007fffff); // flags
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof ExtraFrameAndProcedureInformationMsSymbol);
		String result = symbol.toString().trim();
		assertEquals("FRAMEPROCSYM:\n" + "   Frame size = 00001000 bytes\n" +
			"   Pad size = 00000030 bytes\n" + "   Offset of pad in frame = 00000FD0\n" +
			"   Size of callee save registers = 00000100\n" +
			"   Address of exception handler = 0001:00001100\n" +
			"   Function info: alloca setjmp longjmp inlasm eh  inl_specified seh naked" +
			" gschecks asynceh gsnostackordering wasinlined strict_gs_check safebuffers" +
			" pgo_on valid_pgo_counts opt_for_speed Local=dl Param=dl guardcf" +
			" guardcfw (007FFFFF)", result);
	}

	@Test
	public void testUnknownX1166MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UnknownX1166MsSymbol.PDB_ID);
		// We have no idea of the symbol contents; just probable existence of symbol type x1166.
		writer.putBytes(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UnknownX1166MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNKNOWN_SYMBOL_X1166: Bytes:\n" + "000000 01 02 03 04 05 06 07 08", result);
	}

	@Test
	public void testUnknownX1167MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UnknownX1167MsSymbol.PDB_ID);
		writer.putUnsignedShort(1); // unknown
		writer.putUnsignedShort(2); // unknown
		writer.putUnsignedShort(3); // unknown
		writer.putNullTerminatedUtf8String("UnknownX1167String"); // string 
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UnknownX1167MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNKNOWN_SYMBOL_X1167\n" + "unknownUnsignedShort1: 0001\n" +
			"unknownUnsignedShort2: 0002\n" + "unknownUnsignedShort3: 0003\n" +
			"String: UnknownX1167String", result);
	}

	@Test
	public void testUnknownX1168MsSymbol() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UnknownX1168MsSymbol.PDB_ID);
		writer.putInt(2); // we believe this is a count
		writer.putInt(4096); // we are assuming this is a type record index
		writer.putInt(4096); // we are assuming this is a type record index
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsSymbol symbol = SymbolParser.parse(pdb, reader);
        assertTrue(symbol instanceof UnknownX1168MsSymbol);
		String result = symbol.toString().trim();
		assertEquals("UNKNOWN_SYMBOL_X1168: Type List: {DummyMsType, DummyMsType}", result);
	}

	//==============================================================================================
	// Private Methods
	//==============================================================================================
	private static byte[] createProcedureMsFlagsBuffer(boolean framePointerPresent,
			boolean interruptReturn, boolean farReturn, boolean doesNotReturn,
			boolean labelNotFallenInto, boolean customCallingConvention, boolean markedNoInline,
			boolean hasDebugInfo) {
		int flags = 0;
		flags |= (hasDebugInfo ? 1 : 0);
		flags <<= 1;
		flags |= (markedNoInline ? 1 : 0);
		flags <<= 1;
		flags |= (customCallingConvention ? 1 : 0);
		flags <<= 1;
		flags |= (labelNotFallenInto ? 1 : 0);
		flags <<= 1;
		flags |= (doesNotReturn ? 1 : 0);
		flags <<= 1;
		flags |= (farReturn ? 1 : 0);
		flags <<= 1;
		flags |= (interruptReturn ? 1 : 0);
		flags <<= 1;
		flags |= (framePointerPresent ? 1 : 0);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedByte(flags);
		return writer.get();
	}

	private static byte[] createLocalVariableFlagsBuffer(boolean isParameter, boolean addressTaken,
			boolean compilerGenerated, boolean isAggregateWhole, boolean isAggregatedPart,
			boolean isAliased, boolean isAlias, boolean isFunctionReturnValue,
			boolean isOptimizedOut, boolean isEnregisteredGlobal, boolean isEnregisteredStatic) {
		int flags = 0;
		flags |= (isEnregisteredStatic ? 1 : 0);
		flags <<= 1;
		flags |= (isEnregisteredGlobal ? 1 : 0);
		flags <<= 1;
		flags |= (isOptimizedOut ? 1 : 0);
		flags <<= 1;
		flags |= (isFunctionReturnValue ? 1 : 0);
		flags <<= 1;
		flags |= (isAlias ? 1 : 0);
		flags <<= 1;
		flags |= (isAliased ? 1 : 0);
		flags <<= 1;
		flags |= (isAggregatedPart ? 1 : 0);
		flags <<= 1;
		flags |= (isAggregateWhole ? 1 : 0);
		flags <<= 1;
		flags |= (compilerGenerated ? 1 : 0);
		flags <<= 1;
		flags |= (addressTaken ? 1 : 0);
		flags <<= 1;
		flags |= (isParameter ? 1 : 0);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(flags);
		return writer.get();
	}

	private static byte[] createLocalVariableAttributesBuffer(long offset, int segment,
			byte[] localVariableFlagsBuffer) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(offset);
		writer.putUnsignedShort(segment);
		writer.putBytes(localVariableFlagsBuffer);
		return writer.get();
	}

	private static byte[] createLocalVariableAddressRangeBuffer(long offset, int sectionStart,
			int length) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(offset);
		writer.putUnsignedShort(sectionStart);
		writer.putUnsignedShort(length);
		return writer.get();
	}

	private static byte[] createLocalVariableAddressGapBuffer(int gapStartOffset, int length) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(gapStartOffset);
		writer.putUnsignedShort(length);
		return writer.get();
	}

	private static void compressData(PdbByteWriter writer, long int32) {
		if (int32 < 0x80L) {
			writer.putUnsignedByte((int) int32);
		}
		else if (int32 < 0x4000L) {
			writer.putUnsignedByte((int) (((int32 >> 8) & 0x3f) | 0x80));
			writer.putUnsignedByte((int) (int32 & 0xff));
		}
		else if (int32 < 0x20000000L) {
			writer.putUnsignedByte((int) (((int32 >> 24) & 0x1f) | 0xc0));
			writer.putUnsignedByte((int) ((int32 >> 16) & 0xff));
			writer.putUnsignedByte((int) ((int32 >> 8) & 0xff));
			writer.putUnsignedByte((int) (int32 & 0xff));
		}
		else {
			// error.  decompress converts big values to -1.
			// silently fail.
		}
	}

	private static long encodeSignedInt32(long int32) {
		int flagBit = 0x00;
		if (int32 < 0) {
			int32 = -int32;
			flagBit = 0x01;
		}
		return ((int32 & 0x7fffffff) << 1) | flagBit;
	}

	private static byte[] createInstructionAnnotationBuffer(int instructionCode, long int32Param1,
			long int32Param2) {
		PdbByteWriter writer = new PdbByteWriter();
		compressData(writer, instructionCode);
		if (instructionCode == 0x00) {
			writer.putAlign(0);
		}
		else if (instructionCode == 0x0c) {
			compressData(writer, int32Param1);
			compressData(writer, int32Param2);
		}
		else if ((instructionCode == 0x06) || (instructionCode == 0x0a)) {
			compressData(writer, encodeSignedInt32(int32Param1));
		}
		else {
			compressData(writer, int32Param1);
		}
		return writer.get();
	}

	// Code here was copied from the test code for this type, but we just want a buffer of data.
	private byte[] createRegister16MsSymbolBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Register16MsSymbol.PDB_ID);
		writer.putUnsignedShort(4096); // Type index or metadata token
		writer.putUnsignedShort(0x0102); // Register enumerate
		writer.putByteLengthPrefixedUtf8String("registerSymbolName");
		return writer.get();
	}

}
