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
package ghidra.app.plugin.core.comments;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.util.EolComments;
import ghidra.app.util.viewer.field.EolEnablement;
import ghidra.app.util.viewer.field.EolExtraCommentsOption;
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.RollbackException;

public class EolCommentsTest extends AbstractGenericTest {

	private ProgramDB program;

	public EolCommentsTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder();

		builder.createMemory("Test", "0x100", 100);
		builder.createMemory("Test", "0x1001000", 100);
		builder.createMemory("Test", "0x1001200", 100);

		// testAutoPossiblePointerEOL()
		builder.setBytes("0x110", "00 00 01 20");

		// testReferenceToStringData()
		// testReferenceToOffcutStringData()
		// testReferenceToOffcutStringData_UseAbbreviatedCommentOption()
		builder.createEncodedString("1001234", "one.two", StandardCharsets.US_ASCII, false);

		// testReferenceToFunction()
		builder.createFunction("0x1001050");

		program = builder.getProgram();
	}

	@Test
	public void testAutoPossiblePointerEOL() throws Exception {

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("0x110"));

		EolExtraCommentsOption eolOption = createShowAllOption();
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("?  ->  00000120", comments.get(0));
	}

	private EolExtraCommentsOption createShowAllOption() {
		EolExtraCommentsOption eolOption = new EolExtraCommentsOption();
		eolOption.setRepeatable(EolEnablement.ALWAYS);
		eolOption.setRefRepeatable(EolEnablement.ALWAYS);
		eolOption.setAutoData(EolEnablement.ALWAYS);
		eolOption.setAutoFunction(EolEnablement.ALWAYS);
		return eolOption;
	}

	@Test
	public void testReferenceToStringData() throws Exception {

		Command cmd = new AddMemRefCmd(addr("0x1001000"), addr("0x1001234"),
			SourceType.USER_DEFINED, 0, true);
		applyCmd(cmd);

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("0x1001000"));
		EolExtraCommentsOption eolOption = createShowAllOption();
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("= \"one.two\"", comments.get(0));
	}

	@Test
	public void testReferenceToOffcutStringData() throws Exception {

		Address dataStartAddress = addr("0x1001234");
		Address offcutAddress = dataStartAddress.add(2);
		Command cmd =
			new AddMemRefCmd(addr("0x1001000"), offcutAddress, SourceType.USER_DEFINED, 0, true);
		applyCmd(cmd);

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("0x1001000"));

		EolExtraCommentsOption eolOption = createShowAllOption();

		// with this at false, all of the string will be rendered
		eolOption.setUseAbbreviatedComments(false);
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("= \"one.two\"", comments.get(0));
	}

	@Test
	public void testReferenceToFunction_ShowAutomaticFunctionsOff() throws Exception {

		Address dataStartAddress = addr("0x1001234");
		Address offcutAddress = dataStartAddress.add(2);
		Command cmd =
			new AddMemRefCmd(addr("0x1001000"), offcutAddress, SourceType.USER_DEFINED, 0, true);
		applyCmd(cmd);

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("0x1001000"));

		EolExtraCommentsOption eolOption = createShowAllOption();

		// with this at false, all of the string will be rendered
		eolOption.setUseAbbreviatedComments(false);
		eolOption.setAutoFunction(EolEnablement.NEVER);
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("= \"one.two\"", comments.get(0));
	}

	@Test
	public void testReferenceToOffcutStringData_UseAbbreviatedCommentOption() throws Exception {
		//
		// When on, the 'Use Abbreviated Automatic Comments' option will show only the offcut
		// portion of offcut string data.
		//
		Address dataStartAddress = addr("0x1001234");
		Address offcutAddress = dataStartAddress.add(4);
		Command cmd =
			new AddMemRefCmd(addr("0x1001000"), offcutAddress, SourceType.USER_DEFINED, 0, true);
		applyCmd(cmd);

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("0x1001000"));

		EolExtraCommentsOption eolOption = createShowAllOption();

		// with this at true, only the used part of the string will be rendered
		eolOption.setUseAbbreviatedComments(true);
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("= \"two\"", comments.get(0));// full string is one.two
	}

	@Test
	public void testReferenceToFunction_ShowAutomaticFunctions() throws Exception {

		Address from = addr("0x1001000");
		Address toFunction = addr("0x1001050");

		applyCmd(new AddMemRefCmd(from, toFunction, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS,
			0, true));

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(from);

		EolExtraCommentsOption eolOption = createShowAllOption();
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(1, comments.size());
		assertEquals("undefined FUN_01001050()", comments.get(0));
	}

	@Test
	public void testReferenceToFunction_DontShowAutomaticFunctions() throws Exception {

		Address from = addr("0x1001000");
		Address toFunction = addr("0x1001050");

		applyCmd(new AddMemRefCmd(from, toFunction, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS,
			0, true));

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(from);

		EolExtraCommentsOption eolOption = createShowAllOption();

		// with this at false, all of the string will be rendered
		eolOption.setUseAbbreviatedComments(false);
		eolOption.setAutoFunction(EolEnablement.NEVER);
		EolComments eolComments = new EolComments(cu, false, 5, eolOption);

		List<String> comments = eolComments.getAutomaticComment();
		assertEquals(0, comments.size());
	}

	public boolean applyCmd(Command cmd) throws RollbackException {
		return AbstractGhidraHeadlessIntegrationTest.applyCmd(program, cmd);
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}
}
