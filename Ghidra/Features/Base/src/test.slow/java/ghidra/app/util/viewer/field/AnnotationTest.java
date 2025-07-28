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
package ghidra.app.util.viewer.field;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.field.*;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.TestDummyNavigatable;
import ghidra.app.services.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.TestDummyServiceProvider;
import ghidra.framework.project.ProjectDataService;
import ghidra.framework.protocol.ghidra.GhidraURLConnection;
import ghidra.framework.store.FileSystem;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.task.TaskMonitor;

public class AnnotationTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String SYMBOL1_SUFFIX = "_symbol1";

	private static final String OTHER_PROGRAM_NAME = "program2";

	private Program program;

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemoryReference("1001000", "1003d2c", RefType.CONDITIONAL_JUMP,
			SourceType.DEFAULT);
		builder.createMemoryReference("1001000", "1003d5b", RefType.CONDITIONAL_JUMP,
			SourceType.DEFAULT);
		builder.createMemoryReference("1001000", "1003d28", RefType.CONDITIONAL_JUMP,
			SourceType.DEFAULT);

		builder.createLabel("1001000", "ADVAPI32.dll_IsTextUnicode");
		builder.createLabel("1001014", "bob");
		builder.createLabel("1001018", "mySym{0}"); // symbol with braces
		builder.createLabel("1001022", "mySym\\{0\\}"); // symbol with braces escaped

		return builder.getProgram();
	}

	@Test
	public void testSymbolAnnotationWithAddress() {
		String rawComment = "This is a symbol {@sym 01001014} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals(rawComment, fixed);

		// with display string
		rawComment = "This is a symbol {@sym 01001014 bob} annotation.";
		fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals(rawComment, fixed);
	}

	@Test
	public void testSymbolAnnotationWithInvalidAddress() {
		String rawComment = "This is a symbol {@sym 999999} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals(rawComment, fixed);
	}

	@Test
	public void testSymbolAnnotationWithSymbol() {
		String rawComment = "This is a symbol {@sym LAB_01003d2c} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("This is a symbol {@sym 01003d2c} annotation.", fixed);

		// with display string
		rawComment = "This is a symbol {@sym LAB_01003d2c displayText} annotation.";
		fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("This is a symbol {@sym 01003d2c displayText} annotation.", fixed);
	}

	@Test
	public void testSymbolAnnotationWithInvalidSymbol() {
		String rawComment = "This is a symbol {@sym CocoPebbles} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("This is a symbol {@sym CocoPebbles} annotation.", fixed);
	}

	@Test
	public void testNoAnnotation() {
		String rawComment = "This is no symbol annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals(rawComment, fixed);
	}

	@Test
	public void testMixedAnnotationNoSymbolAnnotation() {
		String rawComment = "This is a symbol {@url www.noplace.com} annotation " +
			"with a {@program notepad} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals(rawComment, fixed);
	}

	@Test
	public void testMixedAnnotationWithSymbolAnnotation() {
		String rawComment = "This is a symbol {@sym LAB_01003d2c} annotation " +
			"with a {@program notepad} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("This is a symbol {@sym 01003d2c} annotation " +
			"with a {@program notepad} annotation.", fixed);
	}

	@Test
	public void testSymbolAnnotationAtBeginningOfComment() {
		String rawComment = "{@sym LAB_01003d2c} annotation at the beginning.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("{@sym 01003d2c} annotation at the beginning.", fixed);
	}

	@Test
	public void testSymbolAnnotation_BackToBack() {
		String rawComment = "Test {@sym LAB_01003d2c}{@sym LAB_01003d2c} end.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("Test {@sym 01003d2c}{@sym 01003d2c} end.", fixed);
	}

	@Test
	public void testSymbolAnnotationAtEndOfComment() {
		String rawComment = "Annotation at the end {@sym LAB_01003d2c}";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("Annotation at the end {@sym 01003d2c}", fixed);
	}

	@Test
	public void testSymbolAnnotationAtBeginningAndEndOfComment() {
		String rawComment =
			"{@sym LAB_01003d2c} annotation at the beginning and end {@sym LAB_01003d5b}";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("{@sym 01003d2c} annotation at the " + "beginning and end {@sym 01003d5b}",
			fixed);
	}

	@Test
	public void testSymbolAnnotationAtBeginningAndMiddleAndEndOfComment() {
		String rawComment =
			"{@sym LAB_01003d2c} annotation at the beginning, middle {@sym LAB_01003d28} and " +
				"end {@sym LAB_01003d5b}";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("{@sym 01003d2c} annotation at the beginning, middle {@sym 01003d28} and " +
			"end {@sym 01003d5b}", fixed);
	}

	@Test
	public void testSymbolAnnotationWithValidAndInvalidSymbol() {
		String rawComment = "This is a symbol {@sym LAB_01003d2c} annotation " +
			"with a {@sym FruityPebbles} annotation.";
		String fixed = CommentUtils.fixupAnnotations(rawComment, program);
		assertEquals("This is a symbol {@sym 01003d2c} annotation " +
			"with a {@sym FruityPebbles} annotation.", fixed);
	}

	@Test
	public void testSymbolAnnotation_WithBracesInName_Escaped() {
		String rawComment = "This is a symbol {@sym mySym\\{0\\}} annotation";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a symbol mySym{0} annotation", display);
	}

	@Test
	public void testSymbolAnnotation_WithEscapedItemsOutsideOfAnnotation() {
		String rawComment = "This is a foo} symbol {@sym mySym\\{0\\}} annotation {bar";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a foo} symbol mySym{0} annotation {bar", display);
	}

	@Test
	public void testAddressAnnotation_QuotedQuote() {
		String rawComment = "Test {@address 0 \"quote\\\"\"} extra}";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("Test quote\" extra}", display);
	}

	@Test
	public void testAddressAnnotation_EscapedBrace() {
		String rawComment = "Test {@address 0 \"quote\\}\"} blah";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("Test quote} blah", display);
	}

	@Test
	public void testAddressAnnotation_BackslashAndEscapedBrace() {
		String rawComment = "Test {@address 0 \"quote\\\\}\"} blah";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("Test quote\\} blah", display);
	}

	@Test
	public void testAddressAnnotation_BackslashBackslash() {
		String rawComment = "Test {@address 0 \"quote\\\\\"} blah";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("Test quote\\ blah", display);
	}

	@Test
	public void testAddressAnnotation_LonelyBackslash() {
		String rawComment = "Test {@address 0 bo\\b} some text";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("Test bo\\b some text", display);
	}

	@Test
	public void testSymbolAnnotation_FullyEscaped() {
		// We currently don't support rendering escaped annotation characters unless they are 
		// inside of an annotation.
		String rawComment = "This is a symbol \\{@sym bob\\} annotation";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a symbol \\{@sym bob\\} annotation", display);
	}

	@Test
	public void testSymbolAnnotation_LonelyBackslash() {
		// We currently don't support rendering escaped annotation characters unless they are 
		// inside of an annotation.
		String rawComment = "This is a symbol {@sym bob jo\\e} annotation";
		String display = CommentUtils.getDisplayString(rawComment, program);

		// Note: Symbol Annotations ignore display text which means that the symbol name 
		assertEquals("This is a symbol bob annotation", display);
	}

	@Test
	public void testUrlAnnotationWithQuotedSymbolText() {
		String rawComment = "This is a symbol {@url \"https://wwww.site.suffix\"} annotation.";
		String displayString = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a symbol https://wwww.site.suffix annotation.", displayString);
	}

	@Test
	public void testUrlAnnotationWithQuotedSubstituteText() {
		String rawComment =
			"This is a symbol {@url https://wwww.site.suffix \"This is my text\"} annotation.";
		String displayString = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a symbol This is my text annotation.", displayString);
	}

	@Test
	public void testUrlAnnotationWithQuotedSymbolAndSubstituteText() {
		String rawComment =
			"This is a symbol {@url \"https://wwww.site.suffix\" \"This is my text\"} annotation.";
		String displayString = CommentUtils.getDisplayString(rawComment, program);
		assertEquals("This is a symbol This is my text annotation.", displayString);
	}

	@Test
	public void testProgramAnnotation_ProgramNameOnly() {

		String programName = OTHER_PROGRAM_NAME;
		String annotationText = "{@program " + programName + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyNavigatable.navigatedTo(programName));
	}

	@Test
	public void testProgramAnnotation_ProgramNameAndAddress() {

		String programName = OTHER_PROGRAM_NAME;
		String address = "01001014"; // some non-start address
		String annotationText = "{@program " + programName + "@" + address + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName + "@" + address, displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyNavigatable.navigatedTo(programName, address));
	}

	@Test
	public void testProgramAnnotation_ProgramNameAndAddress_InvalidAddress() {

		String programName = OTHER_PROGRAM_NAME;
		String address = "01FFFFFF"; // some non-start address
		String annotationText = "{@program " + programName + "@" + address + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName + "@" + address, displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertErrorDialog("Symbol Not Found");

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyServiceProvider.programClosed(programName));
		assertFalse(spyNavigatable.navigatedTo(programName, address));
	}

	@Test
	public void testProgramAnnotation_ProgramNameAndSymbol() {

		String programName = OTHER_PROGRAM_NAME;
		String symbol = programName + SYMBOL1_SUFFIX;
		String annotationText = "{@program " + programName + "@" + symbol + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName + "@" + symbol, displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyNavigatable.navigatedTo(programName, symbol));
	}

	@Test
	public void testProgramAnnotation_ProgramNameAndSymbol_InvalidSymbol() {

		String programName = OTHER_PROGRAM_NAME;
		String symbol = programName + "_no_such_symbol";
		String annotationText = "{@program " + programName + "@" + symbol + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName + "@" + symbol, displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertErrorDialog("Symbol Not Found");

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyServiceProvider.programClosed(programName));
		assertFalse(spyNavigatable.navigatedTo(programName, symbol));
	}

	@Test
	public void testProgramAnnotation_ProgramNameAndAddress_WithDisplayText() {

		String programName = OTHER_PROGRAM_NAME;
		String symbol = programName + SYMBOL1_SUFFIX;
		String annotationText = "{@program " + programName + "@" + symbol + " \"display text\"}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - display text", displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(programName));
		assertTrue(spyNavigatable.navigatedTo(programName, symbol));
	}

	@Test
	public void testProgramAnnotation_InvalidProgram() {

		String programName = "bad_program";
		String annotationText = "{@program " + programName + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + programName, displayString);

		//
		// When clicking an element with a program name and address, then program should be
		// made active and should be navigated to the given address.
		//
		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertErrorDialog("Program Not Found");

		assertFalse(spyServiceProvider.programOpened(programName));
	}

	@Test
	public void testProgramAnnotation_InvalidPath() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";

		// path in comment
		String otherProgramPath = "folder1/folder2/program_f1_f2.exe";

		// real path
		String realPath = "/folder1/program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, realPath, program);

		String annotationText = "{@program " + otherProgramPath + "@" + addresstring + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + otherProgramPath + "@" + addresstring, displayString);

		//
		// When clicking an element with bad path program should not open
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertErrorDialog("Folder Not Found");

		assertFalse(spyServiceProvider.programOpened(otherProgramPath));
	}

	@Test
	public void testProgramAnnotation_ProgramByPath_PathOnly() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String otherProgramPath = "/folder1/folder2/program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, otherProgramPath, program);

		String annotationText = "{@program " + otherProgramPath + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + otherProgramPath, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(otherProgramPath));
		assertTrue(spyNavigatable.navigatedTo(otherProgramPath));
	}

	@Test
	public void testProgramAnnotation_ProgramByPath_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";
		Address address = program.getAddressFactory().getAddress(addresstring);

		String otherProgramPath = "/folder1/folder2/program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, otherProgramPath, program);

		String annotationText = "{@program " + otherProgramPath + "@" + addresstring + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + otherProgramPath + "@" + addresstring, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(otherProgramPath));
		assertTrue(spyNavigatable.navigatedTo(otherProgramPath, address));

	}

	@Test
	public void testProgramAnnotation_ProgramByPath_Backslashes_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";
		Address address = program.getAddressFactory().getAddress(addresstring);

		String otherProgramPath = "/folder1/folder2/program_f1_f2.exe";
		String annotationPath = "\\folder1\\folder2\\program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, otherProgramPath, program);

		String annotationText = "{@program " + annotationPath + "@" + addresstring + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + annotationPath + "@" + addresstring, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(otherProgramPath));
		assertTrue(spyNavigatable.navigatedTo(otherProgramPath, address));
	}

	@Test
	public void testProgramAnnotation_ProgramByPath_Backslashes_NoFirstSlash_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";
		Address address = program.getAddressFactory().getAddress(addresstring);

		String otherProgramPath = "/folder1/folder2/program_f1_f2.exe";
		String annotationPath = "folder1\\folder2\\program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, otherProgramPath, program);

		String annotationText = "{@program " + annotationPath + "@" + addresstring + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + annotationPath + "@" + addresstring, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(otherProgramPath));
		assertTrue(spyNavigatable.navigatedTo(otherProgramPath, address));

	}

	@Test
	public void testProgramAnnotation_ProgramByPath_NoFirstSlash_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";
		Address address = program.getAddressFactory().getAddress(addresstring);

		String otherProgramPath = "/folder1/folder2/program_f1_f2.exe";
		addFakeProgramByPath(spyServiceProvider, otherProgramPath, program);

		String annotationText = "{@program " + otherProgramPath + "@" + addresstring + "}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + otherProgramPath + "@" + addresstring, displayString);

		//
		// When clicking an element with only a program name, the result is that the program
		// should be opened
		//
		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(otherProgramPath));
		assertTrue(spyNavigatable.navigatedTo(otherProgramPath, address));
	}

	@Test
	public void testGhidraLocalUrlAnnotation_Program_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";

		String pathname = "/a/b/prog";
		String url = "ghidra:/folder/project?" + pathname + "#" + addresstring;
		String annotationText = "{@url \"" + url + "\"}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + url, displayString);

		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(pathname));

		// Navigation performed by ProgramManager not tested due to use of spyServiceProvider
	}

	@Test
	public void testGhidraServerUrlAnnotation_Program_WithAddress() {

		SpyNavigatable spyNavigatable = new SpyNavigatable();
		SpyServiceProvider spyServiceProvider = new SpyServiceProvider();

		String addresstring = "1001000";

		String pathname = "/a/b/prog";
		String url = "ghidra://server/repo" + pathname + "#" + addresstring;
		String annotationText = "{@url \"" + url + "\"}";
		String rawComment = "My comment - " + annotationText;
		AttributedString prototype = prototype();
		FieldElement element =
			CommentUtils.parseTextForAnnotations(rawComment, program, prototype, 0);

		String displayString = element.getText();
		assertEquals("My comment - " + url, displayString);

		AnnotatedTextFieldElement annotatedElement = getAnnotatedTextFieldElement(element);
		click(spyNavigatable, spyServiceProvider, annotatedElement);

		assertTrue(spyServiceProvider.programOpened(pathname));

		// Navigation performed by ProgramManager not tested due to use of spyServiceProvider
	}

	@Test
	public void testUnknownAnnotation() {
		String rawComment = "This is a symbol {@syyyybol bob} annotation";
		String display = CommentUtils.getDisplayString(rawComment, program);
		assertEquals(rawComment, display);
	}

	@Test
	public void testInvalidAnnotation_MissingClosingBracket() {

		String data = "This is an annotated string {@symbol 01001014 with trailing text";

		String display = CommentUtils.getDisplayString(data, program);
		assertEquals(data, display);

		AttributedString prototype = prototype();
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype, 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 1,
			strings.length);
		assertEquals("The text color has been changed even though there is no annotation.",
			prototype.getColor(0), strings[0].getColor(0));
	}

	@Test
	public void testInvalidAnnotation_MissingStartingBracket() {

		String data = "This is an annotated string @symbol 01001014} with trailing text";

		String display = CommentUtils.getDisplayString(data, program);
		assertEquals(data, display);

		AttributedString prototype = prototype();
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype, 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 1,
			strings.length);
		assertEquals("The text color has been changed even though there is no annotation.",
			prototype.getColor(0), strings[0].getColor(0));
	}

	@Test
	public void testInvalidAnnotation_MissingAttributes_MatchesKnownAnnotation() {

		String data = "Uh oh, here we go: annotation 2: {@symbol }";
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype(), 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 2,
			strings.length);
		assertEquals("Did not get the expected error annotation string color.", Messages.ERROR,
			strings[1].getColor(0));
	}

	@Test
	public void testInvalidAnnotation_MissingAttributes_DoesNotMatchKnownAnnotation() {

		// we do not detect an annotation in this string since there is no space after 'symbol'
		String data = "Uh oh, here we go: annotation 2: {@symbol}";

		String display = CommentUtils.getDisplayString(data, program);
		assertEquals(data, display);

		AttributedString prototype = prototype();
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype, 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 1,
			strings.length);
		assertEquals("The text color has been changed even though there is no annotation.",
			prototype.getColor(0), strings[0].getColor(0));
	}

	@Test
	public void testInvalidAnnotation_NoSuchSymbol() {

		// valid annotation, invalid symbol
		String data = "This is an annotated string {@symbol 01001001}";
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype(), 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 2,
			strings.length);
		assertEquals("Did not get the expected error annotation string color.", Messages.ERROR,
			strings[1].getColor(0));
	}

	@Test
	public void testCommentWithNoText() {

		// test no text
		String data = "";
		FieldElement fieldElement =
			CommentUtils.parseTextForAnnotations(data, program, prototype(), 0);
		FieldElement[] strings = getNumberOfSubFieldElements(fieldElement);
		assertEquals("Unexpected number of AttributedStrings from comment text.", 1,
			strings.length);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void click(Navigatable navigatable, ServiceProvider sp,
			AnnotatedTextFieldElement annotatedElement) {

		// this may show an error dialog; invoke later
		runSwingLater(() -> annotatedElement.handleMouseClicked(navigatable, sp));
		waitForSwing();
	}

	private AnnotatedTextFieldElement getAnnotatedTextFieldElement(FieldElement element) {

		assertThat(element, instanceOf(CompositeFieldElement.class));

		// Note: the annotated element is a sub-element of the composite field element
		CompositeFieldElement composite = (CompositeFieldElement) element;
		FieldElement[] parts = (FieldElement[]) getInstanceField("fieldElements", composite);
		for (FieldElement fe : parts) {
			if (fe instanceof AnnotatedTextFieldElement) {
				return (AnnotatedTextFieldElement) fe;
			}
		}

		fail("No annotated text field element found in the given field element");
		return null;
	}

	@SuppressWarnings("deprecation")
	private FontMetrics getFontMetrics() {
		Font testFont = new Font("Times New Roman", Font.BOLD, 12);
		FontMetrics fm = Toolkit.getDefaultToolkit().getFontMetrics(testFont);
		return fm;
	}

	private AttributedString prototype() {
		FontMetrics fontMetrics = getFontMetrics();
		AttributedString prototypeString = new AttributedString("", Colors.FOREGROUND, fontMetrics);
		return prototypeString;
	}

	private FieldElement[] getNumberOfSubFieldElements(FieldElement fieldElement) {
		if (fieldElement instanceof CompositeFieldElement) {
			return (FieldElement[]) getInstanceField("fieldElements", fieldElement);
		}
		return new FieldElement[] { fieldElement };
	}

	private void addFakeProgramByPath(SpyServiceProvider provider, String path, Program p) {

		SpyProjectDataService spyProjectData =
			(SpyProjectDataService) provider.getService(ProjectDataService.class);
		FakeRootFolder root = spyProjectData.fakeProjectData.fakeRootFolder;

		if (StringUtils.isBlank(path) || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}
		else if (path.charAt(path.length() - 1) == FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException("Missing file name in path");
		}
		int ix = path.lastIndexOf(FileSystem.SEPARATOR);
		String folderPath = "/";
		if (ix > 0) {
			folderPath = path.substring(0, ix);
		}
		String programName = path.substring(ix + 1);

		try {
			DomainFolder parent = ProjectDataUtils.createDomainFolderPath(root, folderPath);
			parent.createFile(programName, p, TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			failWithException("Unable to create a dummy domain file", e);
		}
	}

	private void assertErrorDialog(String title) {
		Window window = waitForWindowByTitleContaining(title);
		runSwing(() -> window.setVisible(false));
		waitForSwing(); // let post-dialog processing happen		
	}

//==================================================================================================
// Fake/Spy Classes
//==================================================================================================	

	private class SpyServiceProvider extends TestDummyServiceProvider {

		private SpyProgramManager spyProgramManager = new SpyProgramManager();
		private SpyProjectDataService spyProjectDataService = new SpyProjectDataService();
		private SpyGoToService spyGoToService = new SpyGoToService();

		@SuppressWarnings("unchecked")
		@Override
		public <T> T getService(Class<T> serviceClass) {
			if (serviceClass == ProgramManager.class) {
				return (T) spyProgramManager;
			}
			else if (serviceClass == ProjectDataService.class) {
				return (T) spyProjectDataService;
			}
			else if (serviceClass == GoToService.class) {
				return (T) spyGoToService;
			}
			return super.getService(serviceClass);
		}

		boolean programOpened(String path) {
			return spyProgramManager.programOpened(path);
		}

		boolean programClosed(String path) {
			return spyProgramManager.programClosed(path);
		}
	}

	private class SpyProjectDataService implements ProjectDataService {

		private FakeProjectData fakeProjectData = new FakeProjectData();

		@Override
		public ProjectData getProjectData() {
			return fakeProjectData;
		}
	}

	private class FakeProjectData extends TestDummyProjectData {

		private FakeRootFolder fakeRootFolder = new FakeRootFolder();

		@Override
		public DomainFolder getRootFolder() {
			return fakeRootFolder;
		}

		@Override
		public DomainFolder getFolder(String path, DomainFolderFilter filter) {
			return ProjectDataUtils.getDomainFolder(fakeRootFolder, path, filter);
		}

		@Override
		public DomainFile getFile(String path, DomainFileFilter filter) {
			if (StringUtils.isBlank(path) || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
				throw new IllegalArgumentException(
					"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
			}
			else if (path.charAt(path.length() - 1) == FileSystem.SEPARATOR_CHAR) {
				throw new IllegalArgumentException("Missing file name in path");
			}
			int ix = path.lastIndexOf(FileSystem.SEPARATOR);

			DomainFolder folder;
			String fileName = path;
			if (ix > 0) {
				folder = getFolder(path.substring(0, ix), filter);
				fileName = path.substring(ix + 1);
			}
			else {
				folder = getRootFolder();
			}
			if (folder != null) {
				DomainFile file = folder.getFile(fileName);
				if (file != null && filter.accept(file)) {
					return file;
				}
			}
			return null;
		}
	}

	private class FakeRootFolder extends TestDummyDomainFolder {

		public FakeRootFolder() {
			super(null, "Fake Root Folder");
			files.add(new TestDummyDomainFile(this, OTHER_PROGRAM_NAME, "Program"));
		}

		@Override
		public boolean isInWritableProject() {
			return true;
		}
	}

	private class SpyProgramManager extends TestDummyProgramManager {

		private Set<String> openedPrograms = new HashSet<>();
		private Set<String> closedPrograms = new HashSet<>();

		private Program generateProgram(String pathname, String name) {
			try {
				ProgramBuilder builder = new ProgramBuilder();
				builder.setName(pathname);
				builder.createMemory(".text", "0x1001000", 0x100);
				builder.createLabel("1001014", name + SYMBOL1_SUFFIX);
				return builder.getProgram();
			}
			catch (Exception e) {
				failWithException("Unable to build program", e);
				return null;
			}
		}

		@Override
		public Program openProgram(URL ghidraURL, int state) {
			try {
				GhidraURLConnection c = new GhidraURLConnection(ghidraURL);
				String folderpath = c.getFolderPath();
				String name = c.getFolderItemName();
				String pathname = folderpath;
				if (!pathname.endsWith(FileSystem.SEPARATOR)) {
					pathname += FileSystem.SEPARATOR;
				}
				pathname += name;
				openedPrograms.add(name);

				Program p = generateProgram(pathname, name);

				// NOTE: URL ref navigation not performed

				return p;
			}
			catch (MalformedURLException e) {
				failWithException("Bad URL", e);
			}
			return null;
		}

		@Override
		public Program openProgram(DomainFile domainFile, int version, int state) {
			String name = domainFile.getName();
			String pathname = domainFile.getPathname();
			openedPrograms.add(name);
			return generateProgram(pathname, name);
		}

		@Override
		public boolean closeProgram(Program p, boolean ignoreChanges) {
			String name = FilenameUtils.getName(p.getName());
			closedPrograms.add(name);
			closedPrograms.add(p.getName());
			return true;
		}

		boolean programOpened(String path) {
			String name = FilenameUtils.getName(path);
			return openedPrograms.contains(name);
		}

		boolean programClosed(String path) {
			return closedPrograms.contains(path);
		}
	}

	private class SpyGoToService extends TestDummyGoToService {

		@Override
		public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program p) {
			return navigatable.goTo(p, loc);
		}
	}

	private class SpyNavigatable extends TestDummyNavigatable {

		private ProgramLocation lastLocation;

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public boolean goTo(Program p, ProgramLocation location) {

			Address address = location.getAddress();
			Memory memory = p.getMemory();
			if (!memory.contains(address)) {
				// this lets us change flow in the annotation by passing an address not in memory
				return false;
			}

			lastLocation = location;
			return true;
		}

		boolean navigatedTo(String programName) {
			if (lastLocation == null) {
				return false;
			}

			// check for a name or a path that ends with the name--it makes testing easier
			Program locationProgram = lastLocation.getProgram();
			return locationProgram.getName().equals(programName) ||
				locationProgram.getName().endsWith(programName);
		}

		/**
		 * Try to navigate to the given program/symbol pair
		 * @param programName Program to navigate to
		 * @param symbolName Name of symbol to navigate to
		 * @return true if can navigate to given program@symbol, else false
		 */
		boolean navigatedTo(String programName, String symbolName) {

			if (!navigatedTo(programName)) {
				return false;
			}

			String text = lastLocation.getAddress().toString();
			if (lastLocation instanceof LabelFieldLocation) {
				Symbol symbol = ((LabelFieldLocation) lastLocation).getSymbol();
				text = symbol.getName();
			}

			if (text.equals(symbolName)) {
				return true;
			}

			return false;
		}

		/**
		 * Try to navigate to the given program/address pair
		 * @param programName Program to navigate to
		 * @param address Address to navigate to
		 * @return true if can navigate to given program@address, else false
		 */
		boolean navigatedTo(String programName, Address address) {

			if (!navigatedTo(programName)) {
				return false;
			}

			Address navAddress = lastLocation.getAddress();

			// if address, convert to long and compare
			if (navAddress.equals(address)) {
				return true;
			}

			return false;
		}
	}
}
