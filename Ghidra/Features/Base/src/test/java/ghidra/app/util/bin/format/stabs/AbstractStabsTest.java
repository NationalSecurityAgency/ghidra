package ghidra.app.util.bin.format.stabs;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

import org.junit.After;
import org.junit.Before;

import generic.test.TestUtils;

public abstract class AbstractStabsTest extends AbstractGhidraHeadlessIntegrationTest {

	protected static final String TEST_FILE_NAME = "main.c";
	protected static final CategoryPath TEST_PATH =
		new CategoryPath(StabsParser.STABS_PATH, TEST_FILE_NAME);

	protected Program program;
	protected DataTypeManager dtm;
	protected StabsParser parser;
	private final List<String> stabs;
	private int id;

	protected AbstractStabsTest() {
		super();
		try {
			this.stabs = getStabs();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	protected List<String> getStabs() throws IOException {
		return Collections.emptyList();
	}

	protected AbstractStabsTest(String[] stabs) {
		super();
		this.stabs = Arrays.asList(stabs);
	}

	protected Program getProgram() throws Exception {
		return new ProgramBuilder("stabs", ProgramBuilder._X64).getProgram();
	}

	protected StabsTypeDescriptor getType(String stab) throws Exception {
		parser.parse(List.of(stab));
		return parser.getType(stab);
	}

	@Before
    public void setup() throws Exception {
		program = getProgram();
		dtm = program.getDataTypeManager();
		id = program.startTransaction("Stabs Test");
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		TestUtils.setInstanceField("isEnabled", analysisMgr, Boolean.FALSE);
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		this.parser = new StabsParser(program);
		parser.parse(stabs);
	}
	
	@After
	public void teardown() {
		program.endTransaction(id, true);
	}

}
