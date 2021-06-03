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
package ghidra.app.plugin.core.string.variadic;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;

public class FormatStringParserTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {

		builder = new ProgramBuilder("FormatStringParserTest", ProgramBuilder._TOY, this);
		assertNotNull(builder);
		program = builder.getProgram();
		assertNotNull(program);

	}

	// Determines whether null is properly returned for
	// invalid format Strings. Each String is invalid due to
	// either (1) invalid conversion specifier, (2) invalid
	// length modifier, or (3) placeholder incorrectly used
	@Test
	public void testInvalidFormatString() {

		runFormatTest("%r", null, true); // r is not a conversion specifier
		runFormatTest("%%%lw", null, true); // w is not a conversion specifier
		runFormatTest("%#0*.*ld", null, false); // scanf doesn't use flags or period
		runFormatTest("%d::%%%ld%z", null, true); // z is not a conversion specifier
		runFormatTest("thisisatest%%%#**u", null, true); // two consecutive astericks
		runFormatTest("%#0'*rd", null, true); // r is not length modifier
		runFormatTest("%%%#'*md", null, true); // m is not length modifier
		runFormatTest("%*.**d", null, true); // two consecutive astericks
		runFormatTest("%lD", null, true); // D is not a conversion specifier
		runFormatTest("%-0+**d", null, false); // scanf doesn't use flags, two consecutive astericks
		runFormatTest("%-0+*.*d", null, false); // scanf doesn't use flags or period
		runFormatTest("%2.3d", null, false); // scanf doesn't use period
		runFormatTest("%*1$d %d\n", null, true); // If one placeholder specifies parameter, the others must too
		runFormatTest("%2$d %d\n", null, true); // If one placeholder specifies parameter, the others must too

	}

	// Tests format strings for scanf which have expected types of pointers instead
	// of standard format strings
	@Test
	public void testScanfFormatString() {

		DataType[] expectedTypes1 =
			{ program.getDataTypeManager().getPointer(new IntegerDataType()) };
		runFormatTest("%d", expectedTypes1, false);
		DataType[] expectedTypes2 =
			{ program.getDataTypeManager().getPointer(new IntegerDataType()),
				program.getDataTypeManager().getPointer(new ShortDataType()) };

		runFormatTest("%d%hi", expectedTypes2, false);

		DataType[] expectedTypes3 =
			{ program.getDataTypeManager().getPointer(new PointerDataType(DataType.VOID)),
				program.getDataTypeManager().getPointer(new CharDataType()) };
		runFormatTest("%p%*d%s", expectedTypes3, false);

		DataType[] expectedTypes4 =
			{ program.getDataTypeManager().getPointer(new LongDoubleDataType()),
				program.getDataTypeManager().getPointer(new CharDataType()),
				program.getDataTypeManager().getPointer(new PointerDataType(DataType.VOID)) };

		runFormatTest("!:%12La%*d+=%2s%3p%*20d", expectedTypes4, false);

	}

	// Tests format strings that are more complex, containing less commonly
	// used format patterns and more '%' characters
	@Test
	public void testComplexFormatString() {
		DataType[] expectedTypes1 =
			{ program.getDataTypeManager().getPointer(new IntegerDataType()), };
		runFormatTest("#12%n\nd2", expectedTypes1, true);

		DataType[] expectedTypes2 =
			{ program.getDataTypeManager().getPointer(new CharDataType()), new LongDataType() };
		runFormatTest("#thisisatest%+-4.12s%#.1lin\nd2", expectedTypes2, true);

		DataType[] expectedTypes3 =
			{ new PointerDataType(DataType.VOID), new LongDoubleDataType(),
				new UnsignedCharDataType() };
		runFormatTest("%01.3pp%%%#1.2Lg%%%%%hhXxn2", expectedTypes3, true);

		DataType[] expectedTypes4 = { new IntegerDataType(), new IntegerDataType(),
			new UnsignedCharDataType(), new IntegerDataType(), new LongDoubleDataType() };
		runFormatTest("%0#+-*.*hhX%%%.*La", expectedTypes4, true);
		DataType[] expectedTypes5 = { new IntegerDataType(),

			program.getDataTypeManager().getPointer(new IntegerDataType()), new IntegerDataType(),
			program.getDataTypeManager().getPointer(new WideCharDataType()), new IntegerDataType(),
			new LongDoubleDataType() };
		runFormatTest("%.*n%*C%%%%%.*LE", expectedTypes5, true);

	}

	// Tests format strings that use astericks to add another int
	// argument to determine field width or precision
	@Test
	public void testAsterickFormatString() {
		DataType[] expectedTypes1 = { new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%*d", expectedTypes1, true);

		DataType[] expectedTypes2 = { new IntegerDataType(), new LongDataType() };
		runFormatTest("%.*ld", expectedTypes2, true);

		DataType[] expectedTypes3 =
			{ new IntegerDataType(), new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%*.*d", expectedTypes3, true);
		DataType[] expectedTypes4 =
			{ new IntegerDataType(), new IntegerDataType(), new IntegerDataType() };
		runFormatTest("*%%%+-*.*d", expectedTypes4, true);

	}

	// Test simple format strings with different length modifiers
	@Test
	public void testLengthModifierFormatString() {
		DataType[] expectedTypes1 =
			{ new LongDataType(), new PointerDataType(LongDataType.dataType) };
		runFormatTest("%ld %ln", expectedTypes1, true);

		DataType[] expectedTypes2 =
			{ new ShortDataType(), new CharDataType(), new PointerDataType(ShortDataType.dataType),
				new PointerDataType(CharDataType.dataType) };
		runFormatTest("%hd %hhi %hn %hhn", expectedTypes2, true);

		DataType[] expectedTypes3 = { new UnsignedShortDataType(), new UnsignedCharDataType() };
		runFormatTest("%hx %hhu", expectedTypes3, true);

		DataType[] expectedTypes4 =
			{ new UnsignedLongDataType(), new LongLongDataType(), new UnsignedLongLongDataType(),
				new PointerDataType(LongLongDataType.dataType) };
		runFormatTest("%lX %lld %llx %lln", expectedTypes4, true);

		DataType[] expectedTypes5 =
			{ new LongDoubleDataType(), new LongLongDataType(), new UnsignedLongLongDataType(),
				new UnsignedShortDataType(), new UnsignedCharDataType() };
		runFormatTest("%LE %lli %llX %hu %hhX", expectedTypes5, true);
	}

	// Test simple format strings with different special length modifiers 
	// using generated default typedefs
	@Test
	public void testSpecialLengthModifierFormatStringDefault() {
		DataType[] expectedTypes1 =
			{ new TypedefDataType("size_t", UnsignedLongDataType.dataType) };
		runFormatTest("%zd", expectedTypes1, true);

		DataType[] expectedTypes2 =
			{ new TypedefDataType("size_t", UnsignedLongDataType.dataType) };
		runFormatTest("%zu", expectedTypes2, true);

		DataType[] expectedTypes3 = { new TypedefDataType("ptrdiff_t", LongDataType.dataType) };
		runFormatTest("%td", expectedTypes3, true);

		DataType[] expectedTypes4 =
			{ new TypedefDataType("size_t", UnsignedLongDataType.dataType) };
		runFormatTest("%tu", expectedTypes4, true);

		DataType[] expectedTypes5 = { new TypedefDataType("intmax_t", LongLongDataType.dataType) };
		runFormatTest("%jd", expectedTypes5, true);

		DataType[] expectedTypes6 =
			{ new TypedefDataType("uintmax_t", UnsignedLongLongDataType.dataType) };
		runFormatTest("%ju", expectedTypes6, true);

		DataType[] expectedTypes7 =
			{ new PointerDataType(new TypedefDataType("intmax_t", LongLongDataType.dataType)) };
		runFormatTest("%jn", expectedTypes7, true);
	}

	// Test simple format strings with different special length modifiers 
	// using predefined typedefs
	@Test
	public void testSpecialLengthModifierFormatStringPredefined() {

		int txId = program.startTransaction("Add TypeDefs");
		try {
			ProgramDataTypeManager dtm = program.getDataTypeManager();
			DataType sizetDt =
				dtm.resolve(new TypedefDataType("size_t", UnsignedLongLongDataType.dataType), null);
			DataType ptrdiftDt =
				dtm.resolve(new TypedefDataType("ptrdiff_t", LongLongDataType.dataType), null);
			DataType intmaxtDt =
				dtm.resolve(new TypedefDataType("intmax_t", LongDataType.dataType), null);
			DataType uintmaxtDt =
				dtm.resolve(new TypedefDataType("uintmax_t", UnsignedLongDataType.dataType), null);

			DataType[] expectedTypes1 = { sizetDt };
			runFormatTest("%zd", expectedTypes1, true);

			DataType[] expectedTypes2 = { sizetDt };
			runFormatTest("%zu", expectedTypes2, true);

			DataType[] expectedTypes3 = { ptrdiftDt };
			runFormatTest("%td", expectedTypes3, true);

			DataType[] expectedTypes4 = { sizetDt };
			runFormatTest("%tu", expectedTypes4, true);

			DataType[] expectedTypes5 = { intmaxtDt };
			runFormatTest("%jd", expectedTypes5, true);

			DataType[] expectedTypes6 = { uintmaxtDt };
			runFormatTest("%ju", expectedTypes6, true);

			DataType[] expectedTypes7 = { new PointerDataType(intmaxtDt) };
			runFormatTest("%jn", expectedTypes7, true);

		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	// Test simple format Strings with different conversion specifiers
	@Test
	public void testConversionSpecFormatString() {
		DataType[] expectedTypes1 = { new IntegerDataType() };
		runFormatTest("%d", expectedTypes1, true);

		DataType[] expectedTypes2 =
			{ new IntegerDataType(), new IntegerDataType(), new UnsignedIntegerDataType(),
				program.getDataTypeManager().getPointer(new CharDataType()) };
		runFormatTest("%i %i %x %s", expectedTypes2, true);

		DataType[] expectedTypes3 = { new IntegerDataType(), new IntegerDataType(),
			program.getDataTypeManager().getPointer(new CharDataType()) };
		runFormatTest("%d %d %s", expectedTypes3, true);

		DataType[] expectedTypes4 = { new DoubleDataType(), new DoubleDataType(),
			new DoubleDataType(), new DoubleDataType(), new UnsignedCharDataType() };
		runFormatTest("%e %f %E %G %c", expectedTypes4, true);

		DataType[] expectedTypes5 = { new UnsignedIntegerDataType(), new UnsignedIntegerDataType(),
			new UnsignedIntegerDataType(), new DoubleDataType(), new DoubleDataType() };
		runFormatTest("%u %x %X %e %g", expectedTypes5, true);
		DataType[] expectedTypes6 = { new IntegerDataType() };
		runFormatTest("%.d", expectedTypes6, true);
	}

	// Format Strings with field widths indicated by the sequence "*m$" 
	// where m is an integer that determines the position in the argument 
	// list of an integer argument
	@Test
	public void testFormatParameters() {
		DataType[] expectedTypes1 = { new IntegerDataType() };
		runFormatTest("%1$d", expectedTypes1, true);

		DataType[] expectedTypes2 = { new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%1$*2$d", expectedTypes2, true);

		DataType[] expectedTypes3 = { new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%1$.*2$d", expectedTypes3, true);

		DataType[] expectedTypes4 = { new IntegerDataType(), new IntegerDataType(),
			new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%1$d:%2$.*3$d:%4$.*3$d\n", expectedTypes4, true);
		DataType[] expectedTypes5 =
			{ new UnsignedIntegerDataType(), new UnsignedIntegerDataType() };

		runFormatTest("%2$d %2$#x; %1$d %1$#x", expectedTypes5, true);

		DataType[] expectedTypes6 =
			{ new UnsignedIntegerDataType(), new IntegerDataType(), new IntegerDataType() };
		runFormatTest("%2$+#*3$d:%2$#x;0-:'.~%1$0*2$d:!2%1$#x", expectedTypes6, true);
		DataType[] expectedTypes7 =
			{ new UnsignedLongLongDataType(), new DoubleDataType(), new IntegerDataType() };
		runFormatTest("%2$+#*3$f:*;`2!%1$#qu", expectedTypes7, true);
	}

	private void runFormatTest(String testString, DataType[] expected, boolean runOutputAnalyzer) {

		FormatStringParser parser = new FormatStringParser(program);
		List<FormatArgument> formatArguments =
			parser.convertToFormatArgumentList(testString, runOutputAnalyzer);
		DataType[] dataTypes = runOutputAnalyzer ? parser.convertToOutputDataTypes(formatArguments)
				: parser.convertToInputDataTypes(formatArguments);
		assertEquivalent(dataTypes, expected);

	}

	private void assertEquivalent(DataType[] actual, DataType[] expected) {

		if (expected == null) {
			assertNull(actual);
			return;
		}
		assertNotNull("Expected args were not produced", actual);
		assertNotNull("Unexpected args were produced", expected);
		assertEquals("Expected arg count differs from actual", actual.length, expected.length);

		for (int i = 0; i < actual.length; i++) {
			assertNotNull("Unexpected null arg returned", actual[i]);
			if (!actual[i].isEquivalent(expected[i])) {
				fail("Expected: " + expected[i] + ", Actual: " + actual[i]);
			}
		}
	}

}
