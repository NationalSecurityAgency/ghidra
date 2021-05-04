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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;
import org.xml.sax.SAXException;

import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;

public class SpecExtensionTest extends AbstractDecompilerTest {
	@Override
	protected String getProgramName() {
		return "Winmine__XP.exe.gzf";
	}

	@Test
	public void test_BadCallotherTarget() {
		String myfixup = "<callotherfixup targetop=\"unknownop\">\n" + " <pcode>\n" +
			"  <input name=\"fcx\"/>\n" + " <body><![CDATA[\n" + "    EAX = fcx + 2;\n" +
			" ]]></body>\n" + " </pcode>\n" + "</callotherfixup>\n";
		String errMessage = null;
		try {
			SpecExtension specExtension = new SpecExtension(program);
			specExtension.addReplaceCompilerSpecExtension(myfixup, TaskMonitor.DUMMY);
			fail("expected exception");
		}
		catch (SleighException | XmlParseException | SAXException | LockException ex) {
			errMessage = ex.getMessage();
		}
		assertTrue(errMessage.contains("CALLOTHER_FIXUP target does not exist"));
	}

	@Test
	public void test_BadExtension() {
		// Document with a p-code compile error
		String myfixup = "<callfixup name=\"mynewthing\">\n" + "  <target name=\"targ1\"/>\n" +
			"  <pcode>\n" + "    <body><![CDATA[\n" + "    *ESP = 1000:4;\n" +
			"    ESP = blahhh - 4;\n" + "    ]]></body>\n" + "  </pcode>\n" + "</callfixup>\n";
		String errMessage = null;
		SpecExtension specExtension = new SpecExtension(program);
		try {
			specExtension.addReplaceCompilerSpecExtension(myfixup, TaskMonitor.DUMMY);
		}
		catch (SleighException | XmlParseException | SAXException | LockException ex) {
			errMessage = ex.getMessage();
		}
		assertTrue(errMessage.contains("halting compilation"));

		// Document with an XML parsing problem
		myfixup = "<callfixup name=\"mynewthing\"> </badendtag>";
		errMessage = null;
		String subError = null;
		setErrorsExpected(true);
		try {
			specExtension.testExtensionDocument(myfixup);
			fail("expected exception");
		}
		catch (Exception e) {
			errMessage = e.getMessage();
			subError = e.getCause().getMessage();
		}
		setErrorsExpected(true);
		assertTrue(errMessage.contains("Invalid compiler specification"));
		assertTrue(subError.contains("must be terminated by the matching"));

		// Document that does not validate against the grammar
		myfixup = "<callfixup> <pcode> <body><![CDATA[ESP = 1000;\n]]></body></pcode></callfixup>";
		errMessage = null;
		try {
			specExtension.testExtensionDocument(myfixup);
			fail("expected exception");
		}
		catch (Exception e) {
			errMessage = e.getMessage();
		}
		assertTrue(errMessage.contains("Could not find attribute: name"));
	}

	@Test
	public void test_ExtensionNameCollision() {
		// Legal document that would overwrite a core callfixup
		String myfixup =
			"<callfixup name=\"alloca_probe\"><pcode><body>ESP = ESP - 4;</body></pcode></callfixup>";
		String errMessage = null;
		SpecExtension specExtension = new SpecExtension(program);
		try {
			specExtension.addReplaceCompilerSpecExtension(myfixup, TaskMonitor.DUMMY);
			fail("expected exception");
		}
		catch (SleighException | XmlParseException | SAXException | LockException ex) {
			errMessage = ex.getMessage();
		}
		assertTrue(errMessage.contains("Extension cannot replace"));
	}

	@Test
	public void test_PrototypeExtension() {
		decompile("100272e");
		ClangTextField line = getLineContaining("FUN_010026a7(pHVar1);");
		assertNotNull(line);
		CompilerSpec cspec = program.getCompilerSpec();
		PrototypeModel defaultModel = cspec.getDefaultCallingConvention();
		StringBuilder buffer = new StringBuilder();
		defaultModel.saveXml(buffer, cspec.getPcodeInjectLibrary());
		String defaultString = buffer.toString();
		// Replace the output register EAX with ECX
		defaultString = defaultString.replace("<addr space=\"register\" offset=\"0x0\"/>",
			"<addr space=\"register\" offset=\"4\"/>");
		// Change the name
		defaultString = defaultString.replace("name=\"__stdcall\"", "name=\"myproto\"");
		SpecExtension specExtension = new SpecExtension(program);
		int id1 = program.startTransaction("Test prototype install");
		try {
			specExtension.addReplaceCompilerSpecExtension(defaultString, TaskMonitor.DUMMY);
		}
		catch (LockException | SleighException | SAXException | XmlParseException ex) {
			fail("Unexpected exception: " + ex.getMessage());
		}
		program.endTransaction(id1, true);
		PrototypeModel myproto = cspec.getCallingConvention("myproto");
		assertNotNull(myproto);

		int id = program.startTransaction("test extension install");
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x100112c);
		Function func = program.getFunctionManager().getReferencedFunction(addr);
		boolean changeWorks = true;
		try {
			func.setCallingConvention("myproto");
		}
		catch (InvalidInputException e) {
			changeWorks = false;
		}
		program.endTransaction(id, true);
		assertTrue(changeWorks);

		decompile("100272e");
		// Look for the affect of ECX being the output register
		line = getLineContaining("FUN_010026a7(extraout_EAX);");
		assertNotNull(line);

		int id3 = program.startTransaction("Change eval model");
		Options options = program.getOptions(ProgramCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME);
		options.setString(ProgramCompilerSpec.EVALUATION_MODEL_PROPERTY_NAME, "myproto");
		program.endTransaction(id3, true);

		PrototypeModel evalModel =
			program.getCompilerSpec().getPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT);
		ParamList.WithSlotRec res = new ParamList.WithSlotRec();
		Address ecxAddr = program.getAddressFactory().getRegisterSpace().getAddress(4);
		boolean outExists = evalModel.possibleOutputParamWithSlot(ecxAddr, 4, res);
		assertTrue(outExists);

		int id2 = program.startTransaction("test extension removal");
		try {
			specExtension.removeCompilerSpecExtension("prototype_myproto", TaskMonitor.DUMMY);
		}
		catch (LockException | CancelledException ex) {
			fail("Unexpected exception: " + ex.getMessage());
		}
		program.endTransaction(id2, true);
		myproto = cspec.getCallingConvention("myproto");
		assertNull(myproto);
		assertFalse(func.getCallingConventionName().equals("myproto"));
		evalModel =
			program.getCompilerSpec().getPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT);
		assertEquals(evalModel.getName(), "__stdcall");
	}

	@Test
	public void test_CallFixupExtension() {
		String myfixup = "<callfixup name=\"mynewthing\">\n" + "  <target name=\"targ1\"/>\n" +
			"  <pcode>\n" + "    <body><![CDATA[\n" + "    *ESP = 1000:4;\n" +
			"    ESP = ESP - 4;\n" + "    *:4 ESP = inst_next;\n" + "    ]]></body>\n" +
			"  </pcode>\n" + "</callfixup>\n";
		SpecExtension specExtension = new SpecExtension(program);
		int id1 = program.startTransaction("test extension install");
		try {
			specExtension.addReplaceCompilerSpecExtension(myfixup, TaskMonitor.DUMMY);
		}
		catch (LockException | SleighException | SAXException | XmlParseException ex) {
			fail("Unexpected exception: " + ex.getMessage());
		}
		program.endTransaction(id1, true);
		PcodeInjectLibrary library = program.getCompilerSpec().getPcodeInjectLibrary();
		InjectPayloadSleigh[] programPayloads = library.getProgramPayloads();
		assertEquals(programPayloads.length, 1);
		InjectPayload payload = programPayloads[0];
		assertTrue(programPayloads[0] instanceof InjectPayloadCallfixup);
		InjectPayloadCallfixup callfixup = (InjectPayloadCallfixup) payload;
		List<String> targets = callfixup.getTargets();
		assertEquals(targets.size(), 1);
		assertEquals(targets.get(0), "targ1");
		assertEquals(payload.getName(), "mynewthing");
		assertTrue(payload.isFallThru());
		assertFalse(payload.isIncidentalCopy());

		int id = program.startTransaction("test extensions");
		Address firstAddr =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1002607);
		Function func1 = program.getFunctionManager().getFunctionAt(firstAddr);
		func1.setCallFixup("mynewthing");
		Address secondAddr =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10038d7);

		Function func = program.getFunctionManager().getFunctionAt(secondAddr);
		func.setSignatureSource(SourceType.DEFAULT);
		program.endTransaction(id, true);

		decompile("100263c");
		ClangTextField line = getLineContaining("injection: mynewthing");
		assertNotNull(line);
		// injection causes remaining call to look like it takes 1000 as a parameter
		line = getLineStarting("FUN_010038d7(1000);");
		assertNotNull(line);

		// Remove the fixup extension
		int id2 = program.startTransaction("test extension removal");
		try {
			specExtension.removeCompilerSpecExtension("callfixup_mynewthing", TaskMonitor.DUMMY);
		}
		catch (LockException | CancelledException ex) {
			fail("Unexpected exception: " + ex.getMessage());
		}
		program.endTransaction(id2, true);
		programPayloads = library.getProgramPayloads();
		assertNull(programPayloads);

		decompile("100263c");
		line = getLineStarting("FUN_01002607();");
		assertNotNull(line);
		line = getLineStarting("FUN_010038d7();");
		assertNotNull(line);
	}
}
