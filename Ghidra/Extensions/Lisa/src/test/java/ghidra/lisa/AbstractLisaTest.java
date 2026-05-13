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
package ghidra.lisa;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import org.junit.Rule;
import org.junit.experimental.categories.Categories.ExcludeCategory;
import org.junit.rules.TestName;

import com.contrastsecurity.sarif.SarifSchema210;

import db.Transaction;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.app.plugin.core.decompiler.taint.TaintState.QueryType;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lisa.gui.*;
import ghidra.lisa.gui.LisaOptions.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import sarif.SarifController;
import sarif.SarifService;
import sarif.model.SarifDataFrame;

@ExcludeCategory(AbstractLisaTest.class)

public class AbstractLisaTest extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected PluginTool tool;

	protected ProgramManager programManager;
	protected Program program;
	private Function f = null;
	protected final ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

	CodeBrowserPlugin codeBrowserPlugin;
	ListingPanel staticListing;
	ListingPanel dynamicListing;
	DecompilerProvider decompilerProvider;
	DecompilerPanel decompilerPanel;
	TaintPlugin taint;
	LisaPlugin lisa;

	protected TaintOptions taintOptions;
	protected LisaOptions lisaOptions;
	protected String taintTarget = null;
	protected String taintAddr = null;

	protected HashMap<String, List<String>> types;
	protected HashMap<String, List<String>> values;

	@Rule
	public TestName name = new TestName();
	private int pgmIndex;
	
	public AbstractLisaTest() {
		init(0);
	}
	
	public AbstractLisaTest(int n) {
		init(n);
	}

	protected String getProgramName() {
		return "static-" + getClass().getCanonicalName() + "." + name.getMethodName();
	}
	
	public void init(int n) {
		try {
			pgmIndex = n;
			env = new TestEnv();
			tool = env.getTool();
			programManager = tool.getService(ProgramManager.class);
			env.showTool();
			addPlugins();
			f = createSimpleProgramX86_64();
		}
		catch (Throwable e) {
			Msg.error(this, e.getMessage());
		}
		programManager.openProgram(program);
		taintOptions = taint.getOptions();
		lisaOptions = lisa.getOptions();
		lisaOptions.setHeapDomain(HeapDomainOption.DEFAULT);
		lisaOptions.setTypeDomain(TypeDomainOption.DEFAULT);
		lisaOptions.setValueDomain(ValueDomainOption.DEFAULT);
		lisaOptions.setShowTop(true);
		lisaOptions.setShowUnique(true);
	}

	public void runTest() {
		LisaTaintState state = (LisaTaintState) taint.getTaintState();
		state.setSuppressTop(false);
		if (taintTarget != null) {
			state.setTaint(MarkType.SOURCE, f, program.getAddressFactory().getAddress(taintAddr),
				taintTarget);
		}
		monitor.initialize(program.getFunctionManager().getFunctionCount());
		state.queryIndex(program, tool, QueryType.DEFAULT);
		SarifSchema210 data = state.getData();
		SarifService sarifService = taint.getSarifService();
		SarifController controller = sarifService.getController();
		SarifDataFrame df = new SarifDataFrame(data, controller, false);
		List<Map<String, Object>> results = df.getTableResults();
		types = new HashMap<>();
		values = new HashMap<>();
		for (Map<String, Object> map : results) {
			String key = (String) map.get("location");
			key = key.substring(key.indexOf(":") + 1);
			String type = (String) map.get("type");
			String value = (String) map.get("value");
			List<String> list = types.get(key);
			if (list == null) {
				list = new ArrayList<>();
				types.put(key, list);
			}
			list.add(type);
			list = values.get(key);
			if (list == null) {
				list = new ArrayList<>();
				values.put(key, list);
			}
			list.add(value);
		}
		monitor.clearCancelled();
	}

	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		program = new ProgramDB(getProgramName(), lang, cSpec, this);
	}

	protected void createProgram(String languageID, String cSpecID) throws IOException {
		Language language = getLanguageService().getLanguage(new LanguageID(languageID));
		CompilerSpec cSpec = cSpecID == null ? language.getDefaultCompilerSpec()
				: language.getCompilerSpecByID(new CompilerSpecID(cSpecID));
		createProgram(language, cSpec);
	}

	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, monitor);
				return true;
			}
			catch (InvalidNameException | CancelledException e) {
				throw new AssertionError(e);
			}
			catch (IOException e) {
				// Usually "object is busy". Try again.
				return false;
			}
		});
	}

	protected void addPlugins() throws Throwable {
		codeBrowserPlugin = addPlugin(tool, CodeBrowserPlugin.class);
		staticListing = codeBrowserPlugin.getProvider().getListingPanel();
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);
		taint = addPlugin(tool, TaintPlugin.class);
		lisa = addPlugin(tool, LisaPlugin.class);
		TaintState state = TaintState.newInstance(taint, "lisa");
		taint.setTaintState(state);

		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		decompilerPanel = decompilerProvider.getDecompilerPanel();
	}

	private AssemblyBuffer getProgram(int index) throws Throwable {
		return switch (index) {
			case 7 -> getProgram_v7();
			case 6 -> getProgram_v6();
			case 5 -> getProgram_v5();
			case 4 -> getProgram_v4();
			case 3 -> getProgram_v3();
			case 2 -> getProgram_v2();
			case 1 -> getProgram_v1();
			default -> getProgram_v0();
		};
	}
	
	protected AssemblyBuffer getProgram_v0() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("PUSH RBP");
		buf.assemble("MOV RBP, RSP");
		buf.assemble("MOV RAX, 0x4");
		buf.assemble("SUB RAX, 0x5");
		buf.assemble("MOV RDX, RAX");
		buf.assemble("RET");
		return buf;
	}

	protected AssemblyBuffer getProgram_v1() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RCX, 0x3");
		buf.assemble("MOV RDX, 0x9");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JLE 0x%s".formatted(tgt0.add(5)));
		buf.assemble("RET 0x8");
		buf.assemble("SUB RAX, RCX");
		buf.assemble("RET 0x8");
		return buf;
	}

	protected AssemblyBuffer getProgram_v2() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RCX, 0x3");
		buf.assemble("MOV RDX, 0x9");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JLE 0x%s".formatted(tgt0.add(5)));
		buf.assemble("RET 0x8");
		buf.assemble("SUB RAX, RCX");
		buf.assemble("CMP EAX, EDX");
		Address tgt1 = buf.getNext();
		buf.assemble("JG 0x%s".formatted(tgt1.add(5)));  // RAX > 9
		buf.assemble("RET 0x8");
		buf.assemble("ADD RCX, 0x3");
		buf.assemble("SUB RAX, RCX");
		buf.assemble("RET 0x8");
		return buf;
	}

	protected AssemblyBuffer getProgram_v3() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RAX, RAX");
		buf.assemble("MOV RCX, 0x3");
		buf.assemble("MOV RDX, 0x9");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JLE 0x%s".formatted(tgt0.add(11)));   // RAX >= 3
		buf.assemble("SUB RAX, 0x5");   // RAX <= 3
		buf.assemble("MOV RDX, RAX");   // RAX <= -2
		Address tgt1 = buf.getNext();
		buf.assemble("JMP 0x%s".formatted(tgt1.add(10)));
		buf.assemble("CMP EAX, EDX");   // RAX >= 3
		Address tgt2 = buf.getNext();
		buf.assemble("JGE 0x%s".formatted(tgt2.add(10)));  // RAX >= 9
		buf.assemble("ADD RCX, 0x5");   // 3 <= RAX < 9
		buf.assemble("ADD RAX, 0x1F");  // RAX >= 3
		buf.assemble("SAR RAX, 0x3");   // RAX >= -2
		buf.assemble("AND RAX, -4");
		buf.assemble("SUB RAX, 0x5");   
		buf.assemble("SUB RAX, RCX");
		buf.assemble("RET 0x8");
		return buf;
	}

	protected AssemblyBuffer getProgram_v4() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RAX, RAX");
		buf.assemble("MOV RCX, 0x2");
		buf.assemble("MOV RDX, 0x8");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JL 0x%s".formatted(tgt0.add(11)));   // RAX > 4
		buf.assemble("SUB RAX, 0x5");   // RAX <= 3
		buf.assemble("MOV RDX, RAX");   // RAX <= -2
		Address tgt1 = buf.getNext();
		buf.assemble("JMP 0x%s".formatted(tgt1.add(10)));
		buf.assemble("CMP EAX, EDX");   // RAX >= 4
		Address tgt2 = buf.getNext();
		buf.assemble("JG 0x%s".formatted(tgt2.add(10)));  // RAX > 8
		buf.assemble("ADD RCX, 0x5");   // 3 <= RAX <= 8
		buf.assemble("ADD RAX, 0x1F");
		buf.assemble("SAR RAX, 0x3");
		buf.assemble("AND RAX, -4");
		buf.assemble("SUB RAX, 0x5");
		buf.assemble("SUB RAX, RCX");
		buf.assemble("RET 0x8");
		return buf;
	}

	protected AssemblyBuffer getProgram_v5() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RAX, RAX");
		buf.assemble("MOV RCX, 0x3");
		buf.assemble("MOV RDX, 0x8");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JBE 0x%s".formatted(tgt0.add(11)));   // RAX >= 3
		buf.assemble("SUB RAX, 0x5");   // RAX < 3
		buf.assemble("MOV RDX, RAX");   // RAX < 8
		Address tgt1 = buf.getNext();
		buf.assemble("JMP 0x%s".formatted(tgt1.add(10)));
		buf.assemble("CMP EAX, EDX");   // RAX >= 3
		Address tgt2 = buf.getNext();
		buf.assemble("JA 0x%s".formatted(tgt2.add(10)));  // RAX >= 9
		buf.assemble("ADD RCX, 0x5");   // 3 <= RAX < 9
		buf.assemble("ADD RAX, 0x1F");  // RAX >= 3
		buf.assemble("SAR RAX, 0x3");   // RAX >= -2
		buf.assemble("AND RAX, -4");
		buf.assemble("SUB RAX, 0x5");
		buf.assemble("SUB RAX, RCX");
		buf.assemble("RET 0x8");
		return buf;
	}

	protected AssemblyBuffer getProgram_v6() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RAX, RAX");
		buf.assemble("MOV RCX, 0x3");
		buf.assemble("MOV RDX, 0x8");
		buf.assemble("MOV RBX, 0x6");
		buf.assemble("CMP EAX, ECX");
		Address tgt0 = buf.getNext();
		buf.assemble("JLE 0x%s".formatted(tgt0.add(32)));
		Address tgt1 = buf.getNext();
		buf.assemble("CMP RAX, RDX");			// RAX >= 4
		buf.assemble("JG 0x%s".formatted(tgt1.add(27)));
		buf.assemble("CMP AX, BX"); 			// 8 >= RAX >= 4
		Address tgt2 = buf.getNext();
		buf.assemble("JGE 0x%s".formatted(tgt2.add(16)));
		buf.assemble("ADD RCX, 0x1");			// 5 >= RAX >= 4
		buf.assemble("CMP EAX, ECX");
		Address tgt3 = buf.getNext();
		buf.assemble("JA 0x%s".formatted(tgt3.add(5)));
		buf.assemble("RET 0x8");				// RAX == 4
		buf.assemble("RET 0x8");				// RAX == 5
		buf.assemble("RET 0x8");				// 8 >= RAX >= 6
		buf.assemble("RET 0x8");				// RAX >= 9
		buf.assemble("SUB RCX, 0x3");			// 3 >= RAX
		buf.assemble("CMP EAX, ECX");
		Address tgt4 = buf.getNext();
		buf.assemble("JL 0x%s".formatted(tgt4.add(5)));
		buf.assemble("RET 0x8");				// 3 >= RAX >= 1
		buf.assemble("CMP AX, BX"); 			// -1 >= RAX
		Address tgt5 = buf.getNext();
		buf.assemble("JBE 0x%s".formatted(tgt5.add(5)));
		buf.assemble("RET 0x8");				//  bottom
		buf.assemble("RET 0x8");				// -1 >= RAX
		buf.assemble("RET 0x8");				// 
		return buf;
	}

	protected AssemblyBuffer getProgram_v7() throws Throwable {
		Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
		Address entry = addr(program, 0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		buf.assemble("MOV RAX, RAX");
		buf.assemble("MOV RCX, -0x3");
		buf.assemble("MOV RDX, -0x8");
		buf.assemble("MOV RBX, -0x6");
		buf.assemble("CMP ECX, EAX");
		Address tgt0 = buf.getNext();
		buf.assemble("JLE 0x%s".formatted(tgt0.add(32)));
		Address tgt1 = buf.getNext();
		buf.assemble("CMP RDX, RAX");			// RAX >= 4
		buf.assemble("JG 0x%s".formatted(tgt1.add(27)));
		buf.assemble("CMP BX, AX"); 			// 8 >= RAX >= 4
		Address tgt2 = buf.getNext();
		buf.assemble("JGE 0x%s".formatted(tgt2.add(16)));
		buf.assemble("SUB RCX, 0x1");			// 5 >= RAX >= 4
		buf.assemble("CMP ECX, EAX");
		Address tgt3 = buf.getNext();
		buf.assemble("JA 0x%s".formatted(tgt3.add(5)));
		buf.assemble("RET 0x8");				// RAX == 4
		buf.assemble("RET 0x8");				// RAX == 5
		buf.assemble("RET 0x8");				// 8 >= RAX >= 6
		buf.assemble("RET 0x8");				// RAX >= 9
		buf.assemble("ADD RCX, 0x3");			// 3 >= RAX
		buf.assemble("CMP ECX, EAX");
		Address tgt4 = buf.getNext();
		buf.assemble("JL 0x%s".formatted(tgt4.add(5)));
		buf.assemble("RET 0x8");				// 3 >= RAX >= 1
		buf.assemble("CMP BX, AX"); 			// -1 >= RAX
		Address tgt5 = buf.getNext();
		buf.assemble("JBE 0x%s".formatted(tgt5.add(5)));
		buf.assemble("RET 0x8");				//  bottom
		buf.assemble("RET 0x8");				// -1 >= RAX
		buf.assemble("RET 0x8");				// 
		return buf;
	}

	protected Function createSimpleProgramX86_64() throws Throwable {
		createProgram("x86:LE:64:default", "gcc");
		intoProject(program);

		try (Transaction tx = program.openTransaction("Assemble")) {
			ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
			Structure structure = new StructureDataType("MyStruct", 0, dtm);
			structure.add(DWordDataType.dataType, "f1", "");
			structure.add(DWordDataType.dataType, "f2", "");
			structure.add(QWordDataType.dataType, "f3", "");
			structure =
				(Structure) dtm.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);

			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);

			AssemblyBuffer buf = getProgram(pgmIndex);
			Address end = buf.getNext();

			program.getMemory().setBytes(entry, buf.getBytes());

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			Function funFillStruct = program.getFunctionManager()
					.createFunction("simple", entry, new AddressSet(entry, end.previous()),
						SourceType.ANALYSIS);
			funFillStruct.addLocalVariable(new LocalVariableImpl("s", structure, -0x18, program),
				SourceType.ANALYSIS);

			return funFillStruct;
		}
	}

	public static final AssemblySelector NO_16BIT_CALLS = new AssemblySelector() {
		@Override
		public Selection select(AssemblyResolutionResults rr, AssemblyPatternBlock ctx)
				throws AssemblySemanticException {
			for (AssemblyResolvedPatterns res : filterCompatibleAndSort(rr, ctx)) {
				byte[] ins = res.getInstruction().getVals();
				// HACK to avoid 16-bit CALL.... TODO: Why does this happen?
				if (ins.length >= 2 && ins[0] == (byte) 0x66 && ins[1] == (byte) 0xe8) {
					Msg.error(this,
						"Filtered 16-bit call " + NumericUtilities.convertBytesToString(ins));
					continue;
				}
				return new Selection(res.getInstruction().fillMask(), res.getContext());
			}
			throw new AssemblySemanticException(semanticErrors);
		}
	};

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected String typeOf(String key) {
		return of(types, key);
	}

	protected String valueOf(String key) {
		return of(values, key);
	}

	private String of(Map<String, List<String>> map, String key) {
		List<String> list = map.get(key);
		if (list == null) {
			return null;
		}
		if (list.size() == 1) {
			return list.get(0);
		}
		String[] sorted = new String[list.size()];
		list.toArray(sorted);
		Arrays.sort(sorted);
		return Arrays.toString(sorted);
	}

	protected void equalsAssert(Object actual, Object expected) {
		assertEquals(expected, actual);
	}

}
