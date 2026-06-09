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
package ghidra.features.base.replace;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests user input with search options for both one word searchers (renaming labels, datatypes,
 * etc.) and updating multi-word matches (comments)
 */
public class AbstractSearchAndReplaceTest extends AbstractGhidraHeadedIntegrationTest {
	protected static final boolean CASE_SENSITIVE_ON = true;
	protected static final boolean CASE_SENSITIVE_OFF = false;
	protected static final boolean WHOLE_WORD_ON = true;
	protected static final boolean WHOLE_WORD_OFF = false;
	protected static final int SEARCH_LIMIT = 100;
	protected Program program;
	protected ProgramBuilder builder;
	private Set<SearchType> querySearchTypes = new HashSet<>();
	protected SearchType labels;
	protected SearchType functions;
	protected SearchType namespaces;
	protected SearchType classes;
	protected SearchType parameters;
	protected SearchType localVariables;
	protected SearchType comments;
	protected SearchType memoryBlocks;
	protected SearchType dataTypes;
	protected SearchType dataTypeComments;
	protected SearchType fieldNames;
	protected SearchType enumValues;
	protected SearchType programTrees;
	protected SearchType categories;

	@Before
	public void setUp() throws Exception {
		program = buildProgram();

		Map<String, SearchType> typesMap = gatherSearchTypes();

		labels = typesMap.get("Labels");
		namespaces = typesMap.get("Namespaces");
		functions = typesMap.get("Functions");
		classes = typesMap.get("Classes");
		parameters = typesMap.get("Parameters");
		localVariables = typesMap.get("Local Variables");
		comments = typesMap.get("Comments");
		memoryBlocks = typesMap.get("Memory Blocks");
		dataTypes = typesMap.get("Datatypes");
		dataTypeComments = typesMap.get("Datatype Comments");
		fieldNames = typesMap.get("Datatype Fields");
		enumValues = typesMap.get("Enum Values");
		programTrees = typesMap.get("Program Trees");
		categories = typesMap.get("Datatype Categories");
	}

	private Map<String, SearchType> gatherSearchTypes() {
		Set<SearchType> searchTypes = SearchType.getSearchTypes();
		Map<String, SearchType> typesMap = new HashMap<>();
		for (SearchType searchType : searchTypes) {
			typesMap.put(searchType.getName(), searchType);
		}
		return typesMap;
	}

	protected Program buildProgram() throws Exception {
		builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(000), 0x1000);
		return builder.getProgram();
	}

	protected void assertQuickFix(long address, String original, String preview, QuickFix item) {
		assertQuickFix(addr(address), original, preview, item);
	}

	protected void assertQuickFix(String original, String preview, QuickFix item) {
		assertEquals(original, item.getOriginal());
		assertEquals(preview, item.getPreview());
	}

	protected void assertQuickFix(Address address, String original, String preview, QuickFix item) {
		assertEquals(address, item.getAddress());
		assertEquals(original, item.getOriginal());
		assertEquals(preview, item.getPreview());
	}

	protected Address addr(long address) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
	}

	protected List<QuickFix> queryRegEx(String search, String replace, boolean caseSensitive)
			throws CancelledException {
		return query(search, replace, true, caseSensitive, false);
	}

	protected List<QuickFix> query(String search, String replace, boolean caseSensitive,
			boolean wholeWord) throws CancelledException {
		return query(search, replace, false, caseSensitive, wholeWord);
	}

	private List<QuickFix> query(String search, String replace, boolean isRegEx,
			boolean isCaseSensitive, boolean isWholeWord) throws CancelledException {
		SearchAndReplaceQuery query =
			new SearchAndReplaceQuery(search, replace, querySearchTypes, isRegEx, isCaseSensitive,
				isWholeWord, SEARCH_LIMIT);
		ListAccumulator<QuickFix> accumulator = new ListAccumulator<>();
		query.findAll(program, accumulator, TaskMonitor.DUMMY);
		return accumulator.asList();
	}

	protected Symbol createLabel(long address, String name) {
		return builder.createLabel(Long.toHexString(address), name);
	}

	protected Function createFunction(long address, String name, String... paramNames)
			throws Exception {

		Parameter[] params = createParameters(paramNames);
		return builder.createEmptyFunction(name, Long.toHexString(address), 1,
			new Integer16DataType(), params);
	}

	private Parameter[] createParameters(String[] paramNames) throws InvalidInputException {
		Parameter[] params = new Parameter[paramNames.length];
		for (int i = 0; i < paramNames.length; i++) {
			params[i] = new ParameterImpl(paramNames[i], new ByteDataType(), program);
		}
		return params;
	}

	protected Namespace createNamespace(Namespace parent, String name) {
		return builder.createNamespace(name, parent.getName(), SourceType.USER_DEFINED);
	}

	protected MemoryBlock createBlock(String name, int address) {
		return builder.createMemory(name, Long.toHexString(address), 10);
	}

	protected GhidraClass createClass(Namespace parent, String name) throws Exception {
		return builder.createClassNamespace(name, parent.getName(), SourceType.USER_DEFINED);
	}

	protected void createComment(long address, CommentType commentType, String comment) {
		builder.createComment(Long.toHexString(address), comment, commentType.ordinal());
	}

	protected void setSearchTypes(SearchType... searchTypes) {
		querySearchTypes.clear();
		for (SearchType searchType : searchTypes) {
			querySearchTypes.add(searchType);
		}
	}

	protected void sortByAddress(List<QuickFix> results) {
		Collections.sort(results, (a, b) -> a.getAddress().compareTo(b.getAddress()));
	}

	protected void sortByName(List<QuickFix> results) {
		Collections.sort(results, (a, b) -> a.getOriginal().compareTo(b.getOriginal()));
	}

	protected void performAction(QuickFix item) {
		program.withTransaction("test", () -> item.performAction());
	}

	protected DataType addDataType(DataType dt) {
		DataTypeManager dtm = program.getDataTypeManager();
		return program.withTransaction("test", () -> dtm.addDataType(dt, null));
	}

}
