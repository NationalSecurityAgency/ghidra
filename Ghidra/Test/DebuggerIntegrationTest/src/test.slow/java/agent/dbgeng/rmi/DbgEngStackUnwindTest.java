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
package agent.dbgeng.rmi;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.test.category.NightlyCategory;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.decompiler.location.DefaultDecompilerLocation;
import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.stack.vars.*;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.*;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.module.DBTraceStaticMappingManager;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.InvalidNameException;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import junit.framework.AssertionFailedError;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DbgEngStackUnwindTest extends AbstractDbgEngTraceRmiTest {

	Address stackRefInstr;
	protected List<Program> programs;

	CodeBrowserPlugin codeBrowserPlugin;
	ListingPanel staticListing;
	DebuggerListingPlugin listingPlugin;
	VariableValueHoverPlugin valuesPlugin;
	ListingPanel dynamicListing;
	VariableValueHoverService valuesService;
	DebuggerStaticMappingService mappingService;
	DecompilerProvider decompilerProvider;
	DecompilerPanel decompilerPanel;

	record PythonAndTrace(PythonAndConnection conn, ManagedDomainObject mdo)
			implements AutoCloseable {
		public void execute(String cmd) {
			conn.execute(cmd);
		}

		public String executeCapture(String cmd) {
			return conn.executeCapture(cmd);
		}

		@Override
		public void close() throws Exception {
			Exception toThrow = null;
			try {
				conn.close();
			}
			catch (Exception e) {
				toThrow = e;
			}
			try {
				mdo.close();
			}
			catch (Exception e) {
				toThrow = e;
			}
			if (toThrow != null) {
				throw toThrow;
			}
		}
	}

	@SuppressWarnings("resource")
	protected PythonAndTrace startAndSyncPython(ManagedDomainObject mdo) throws Exception {
		PythonAndConnection conn = startAndConnectPython();
		try {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			return new PythonAndTrace(conn, mdo);
		}
		catch (Exception e) {
			conn.close();
			throw e;
		}
	}

	protected long lastSnap(PythonAndTrace conn) {
		return conn.conn.connection().getLastSnapshot(tb.trace);
	}

	@Test
	public void testBasicUnwind() throws Throwable {
		List<String> files = Arrays.asList("kernel32.dll", "expSpin.exe", "ntdll.dll");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			checkRtlUserThreadStartUnwindFrom0(2);
			checkMainUnwindFrom0(1);
			checkSleepUnwindFrom0(0);
		}
	}

	@Test
	public void testUnwindActivateMidStack() throws Throwable {
		List<String> files = Arrays.asList("kernel32.dll", "expSpin.exe", "ntdll.dll");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			traceManager.activateFrame(1);

			checkRtlUserThreadStartUnwindAlt(2);
			checkMainUnwindFrom0(1);
			checkSleepUnwindFrom0(0);
		}
	}

	@Test
	public void testUnwindActivateHighFrame() throws Throwable {
		List<String> files = Arrays.asList("kernel32.dll", "expSpin.exe", "ntdll.dll");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			traceManager.activateFrame(4);

			checkRtlUserThreadStartUnwindAlt(2);
			checkMainUnwindFrom0(1);
			checkSleepUnwindFrom0(0);
		}
	}

	@Test
	public void testBasicUnwindMissingLowFrame() throws Throwable {
		List<String> files = Arrays.asList("expSpin.exe", "ntdll.dll");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			checkRtlUserThreadStartUnwindAlt(1);
			checkMainUnwindFrom0(0);
		}
	}

	@Test
	public void testBasicUnwindMissingMedFrame() throws Throwable {
		List<String> files = Arrays.asList("kernel32.dll", "ntdll.dll");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			checkRtlUserThreadStartUnwindAlt(1);
			checkSleepUnwindFrom0(0);
		}
	}

	@Test
	public void testBasicUnwindMissingHighFrame() throws Throwable {
		List<String> files = Arrays.asList("kernel32.dll", "expSpin.exe");

		addPlugins();

		DomainFile[] dfs = getDomainFiles(files);
		tool.acceptDomainFiles(dfs);

		DomainFile traceDF = getDomainFile("expSpin_dbgeng");
		ManagedDomainObject mdo = new ManagedDomainObject(traceDF, false, false, monitor);
		resyncMappings((Trace) mdo.get());
		tool.acceptDomainFiles(new DomainFile[] { traceDF });

		programs = openPrograms(dfs);

		try (PythonAndTrace conn = startAndSyncPython(mdo)) {
			traceManager.activateSnap(2);

			waitForPass(() -> assertEquals(Boolean.TRUE,
				traceManager.getCurrent().getSnap() == 2));

			checkMainUnwindFrom0(1);
			checkSleepUnwindFrom0(0);
		}
	}

	private void checkSleepUnwindFrom0(int at) throws Throwable {
		programManager.openProgram(programs.get(at));
		VariableValueTable table =
			getTable(programs.get(at), 0x18001b100L, "dwMilliseconds", "Sleep(dwMilliseconds);");
		assertTable(Map.of(
			RowKey.NAME, "Name: dwMilliseconds",
			RowKey.FRAME,
			"Frame: 0 Sleep pc=7ff909fab100 sp=be6c2ff798 base=be6c2ff798",
			RowKey.STORAGE, "Storage: ECX:4",
			RowKey.TYPE, "Type: DWORD",
			RowKey.LOCATION, "Location: ECX:4",
			RowKey.INTEGER, "Integer: (UNKNOWN) 1000, 0x3e8",
			RowKey.VALUE, "Value: (UNKNOWN) 3E8h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	private void checkMainUnwindFrom0(int at) throws Throwable {
		programManager.openProgram(programs.get(at));
		VariableValueTable table =
			getTable(programs.get(at), 0x140001000L, "local_58",
				"for (local_58 = 0; local_58 < 10; local_58 = local_58 + 1) {");
		assertTable(Map.of(
			RowKey.NAME, "Name: local_58",
			RowKey.FRAME,
			"Frame: 1 FUN_140001000 pc=7ff7f73c1040 sp=be6c2ff7a0 base=be6c2ff818",
			RowKey.STORAGE, "Storage: Stack[-0x58]:4",
			RowKey.TYPE, "Type: undefined4",
			RowKey.LOCATION, "Location: be6c2ff7c0:4",
			RowKey.BYTES, "Bytes: (UNKNOWN) 00 00 00 00",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) 00000000h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	private void checkRtlUserThreadStartUnwindFrom0(int at) throws Throwable {
		programManager.openProgram(programs.get(at));
		VariableValueTable table =
			getTable(programs.get(at), 0x18007edd0L, "uVar1", "uVar1 = (*param_1)(param_2);");
		assertTable(Map.of(
			RowKey.NAME, "Name: uVar1",
			RowKey.FRAME,
			"Frame: 4 RtlUserThreadStart pc=7ff90adfedfb sp=be6c2ff890 base=be6c2ff908",
			RowKey.STORAGE, "Storage: EAX:4",
			RowKey.TYPE, "Type: undefined4",
			RowKey.LOCATION, "Location: EAX:4",
			RowKey.INTEGER, "Integer: (UNKNOWN) 3543813394, 0xd33a4d12\n-751153902, -0x2cc5b2ee",
			RowKey.VALUE, "Value: (UNKNOWN) D33A4D12h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	private void checkRtlUserThreadStartUnwindAlt(int at) throws Throwable {
		programManager.openProgram(programs.get(at));
		VariableValueTable table =
			getTable(programs.get(at), 0x18007edd0L, "uVar1", "uVar1 = (*param_1)(param_2);");
		assertTable(Map.of(
			RowKey.NAME, "Name: uVar1",
			RowKey.FRAME,
			"Frame: 4 RtlUserThreadStart pc=7ff90adfedfb sp=be6c2ff890 base=be6c2ff908",
			RowKey.STORAGE, "Storage: EAX:4",
			RowKey.TYPE, "Type: undefined4",
			RowKey.LOCATION, "Location: EAX:4",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) 00000000h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	private VariableValueTable getTable(Program p, long addr, String tokText, String fieldText)
			throws Throwable {
		Address entry = addr(p, addr);
		ProgramLocation pl = new ProgramLocation(p, entry);
		goTo(staticListing, pl);
		Function f = p.getFunctionManager().getFunctionAt(entry);
		HoverLocation loc = findTokenLocation(decompilerPanel, f, tokText, fieldText);
		return getVariableValueTable(loc.pLoc, traceManager.getCurrent(), loc.fLoc, loc.field);
	}

	private DomainFile[] getDomainFiles(List<String> files)
			throws InvalidNameException, CancelledException, IOException {
		DomainFile[] dfs = new DomainFile[files.size()];
		int i = 0;
		for (String fname : files) {
			dfs[i++] = getDomainFile(fname);
		}
		return dfs;
	}

	private DomainFile getDomainFile(String fname)
			throws InvalidNameException, CancelledException, IOException {
		DomainFolder rootFolder = tool.getProject()
				.getProjectData()
				.getRootFolder();
		File f = getTestDataFile(fname + ".gzf");
		return rootFolder.createFile(fname, f, monitor);
	}

	private List<Program> openPrograms(DomainFile[] files) {
		List<Program> progs = new ArrayList<>();
		for (int i = 0; i < files.length; i++) {
			progs.add(programManager.openProgram(files[i]));
		}
		return progs;
	}

	private void resyncMappings(Trace trace)
			throws MalformedURLException, URISyntaxException {
		DomainFolder rootFolder = tool.getProject()
				.getProjectData()
				.getRootFolder();
		DBTraceStaticMappingManager staticMappingManager =
			(DBTraceStaticMappingManager) trace.getStaticMappingManager();
		Collection<? extends TraceStaticMapping> allEntries =
			staticMappingManager.getAllEntries();
		Collection<TraceStaticMapping> newEntries = new HashSet<TraceStaticMapping>();
		for (TraceStaticMapping mapping : allEntries) {
			newEntries.add(mapping);
		}
		try (Transaction tx = trace.openTransaction("Remove .text mapping")) {
			for (TraceStaticMapping mapping : newEntries) {
				mapping.delete();
			}
		}
		for (TraceStaticMapping mapping : newEntries) {
			String previousRoot = mapping.getStaticProgramURL().toString();
			String fileName = previousRoot.substring(previousRoot.lastIndexOf("?/") + 2);
			URL localProjectURL = rootFolder.getLocalProjectURL();
			URL url = new URI(localProjectURL + fileName).toURL();
			try (Transaction tx = trace.openTransaction("Remove .text mapping")) {
				staticMappingManager.add(mapping.getTraceAddressRange(), mapping.getLifespan(),
					url, mapping.getStaticAddress());
			}
		}
	}

	protected void addPlugins() throws Throwable {
		codeBrowserPlugin = addPlugin(tool, CodeBrowserPlugin.class);
		staticListing = codeBrowserPlugin.getProvider().getListingPanel();
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		dynamicListing = listingPlugin.getProvider().getListingPanel();
		//addPlugin(tool, DebuggerControlPlugin.class);
		//addPlugin(tool, DebuggerStaticMappingPlugin.class);
		//addPlugin(tool, DebuggerModelPlugin.class);
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);
		valuesService = valuesPlugin.getHoverService();

		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		decompilerPanel = decompilerProvider.getDecompilerPanel();
		tool.showComponentProvider(decompilerProvider, true);
	}

	public record HoverLocation(ProgramLocation pLoc, FieldLocation fLoc, Field field,
			ClangToken token) {}

	public static <T extends ProgramLocation> HoverLocation findLocation(ListingPanel panel,
			Address address, Class<T> locType, Predicate<T> predicate) {
		Layout layout = panel.getLayout(address);
		int numFields = layout.getNumFields();
		for (int i = 0; i < numFields; i++) {
			Field field = layout.getField(i);
			if (!(field instanceof ListingField listingField)) {
				continue;
			}
			FieldFactory factory = listingField.getFieldFactory();
			int numRows = field.getNumRows();
			for (int r = 0; r < numRows; r++) {
				int numCols = field.getNumCols(r);
				for (int c = 0; c < numCols; c++) {
					ProgramLocation loc = factory.getProgramLocation(r, c, listingField);
					if (!locType.isInstance(loc)) {
						continue;
					}
					if (!predicate.test(locType.cast(loc))) {
						continue;
					}
					return new HoverLocation(loc, new FieldLocation(0, i, r, c), field, null);
				}
			}
		}
		return null;
	}

	public static HoverLocation findVariableLocation(ListingPanel panel, Function function,
			String name) {
		return findLocation(panel, function.getEntryPoint(), VariableLocation.class,
			varLoc -> name.equals(varLoc.getVariable().getName()));
	}

	public static HoverLocation findOperandLocation(ListingPanel panel, Instruction ins,
			Object operand) {
		return findLocation(panel, ins.getAddress(), OperandFieldLocation.class, opLoc -> {
			int subIdx = opLoc.getSubOperandIndex();
			if (subIdx == -1) {
				return false;
			}
			return operand.equals(
				ins.getDefaultOperandRepresentationList(opLoc.getOperandIndex()).get(subIdx));
		});
	}

	public static HoverLocation findTokenLocation(DecompilerPanel decompilerPanel,
			Function function, String tokText, String fieldText) {
		DecompileResults results = waitForValue(() -> {
			ProgramLocation pLoc;
			try {
				pLoc = decompilerPanel.getCurrentLocation();
			}
			catch (NullPointerException e) {
				/**
				 * HACK: There's an unlikely race condition where the layout controller has created
				 * the array of layouts but not fully populated it by the time we ask for the
				 * current location. This may cause a line we inspect to still have null in it and
				 * throw an NPE. Whatever. Just catch the thing and return null so that we try
				 * again. As far as I can tell, this is not indicative of a problem in production,
				 * because the controller won't issue an updated event until that array is fully
				 * populated.
				 */
				return null;
			}
			if (!(pLoc instanceof DecompilerLocation dLoc)) {
				return null;
			}
			DecompileResults dr = dLoc.getDecompile();
			if (dr == null || dr.getFunction() != function) {
				return null;
			}
			return dr;
		});

		return runSwing(() -> {
			Program program = function.getProgram();
			ClangLayoutController layoutController = decompilerPanel.getLayoutController();
			BigInteger numIndexes = layoutController.getNumIndexes();
			for (BigInteger i = BigInteger.ZERO; i.compareTo(numIndexes) < 0; i =
				i.add(BigInteger.ONE)) {
				Layout layout = layoutController.getLayout(i);
				int numFields = layout.getNumFields();
				for (int j = 0; j < numFields; j++) {
					Field field = layout.getField(j);
					if (!(field instanceof ClangTextField clangField)) {
						continue;
					}
					if (!fieldText.equals(field.getText().trim())) {
						continue;
					}
					int numRows = field.getNumRows();
					for (int r = 0; r < numRows; r++) {
						int numCols = field.getNumCols(r);
						for (int c = 0; c < numCols; c++) {
							FieldLocation fLoc = new FieldLocation(i, j, r, c);
							ClangToken token = clangField.getToken(fLoc);
							if (token != null && tokText.equals(token.getText())) {

								Address entryPoint = function.getEntryPoint();
								DecompilerLocationInfo info =
									new DecompilerLocationInfo(entryPoint, results, token,
										i.intValue(), 0);
								DefaultDecompilerLocation loc = token.getMinAddress() == null ? null
										: new DefaultDecompilerLocation(program,
											token.getMinAddress(), info);
								return new HoverLocation(loc, fLoc, field, token);
							}
						}
					}
				}
			}
			return null;
		});
	}

	protected HoverLocation findTokenLocation(Function function, String tokText, String fieldText)
			throws Throwable {
		CompletableFuture<Void> ready = new CompletableFuture<>();
		decompilerPanel.getLayoutController().addLayoutModelListener(new LayoutModelListener() {
			@Override
			public void modelSizeChanged(IndexMapper indexMapper) {
				if (decompilerPanel.getCurrentLocation() != null) {
					ready.complete(null);
				}
			}

			@Override
			public void dataChanged(BigInteger start, BigInteger end) {
			}
		});
		tool.showComponentProvider(decompilerProvider, true);
		ready.get(5, TimeUnit.SECONDS);
		try {
			return findTokenLocation(decompilerPanel, function, tokText, fieldText);
		}
		catch (AssertionFailedError e) {
			throw e;
		}
	}

	protected static void assertTable(Map<RowKey, String> texts, VariableValueTable table) {
		ErrorRow error = (ErrorRow) table.get(RowKey.ERROR);
		if (error != null && !texts.containsKey(RowKey.ERROR)) {
			throw new AssertionError("ErrorRow present", error.error());
		}
		for (Map.Entry<RowKey, String> ent : texts.entrySet()) {
			RowKey key = ent.getKey();
			VariableValueRow row = table.get(key);
			assertNotNull("Missing " + key, row);
			if (key != RowKey.WARNINGS) {
				assertEquals(ent.getValue(), row.toSimpleString());
			}
		}
		assertEquals(texts.size(), table.getNumRows());
	}

	protected VariableValueTable getVariableValueTable(ProgramLocation programLocation,
			DebuggerCoordinates current, FieldLocation fieldLocation, Field field)
			throws Throwable {
		VariableValueTable table = new VariableValueTable();
		StackUnwindWarningSet warnings = new StackUnwindWarningSet();
		waitOn(valuesService.fillVariableValueTable(table, programLocation, current, fieldLocation,
			field, warnings));
		table.add(new WarningsRow(warnings));
		return table;
	}

	public static final AssemblySelector NO_16BIT_CALLS = new AssemblySelector() {
		@Override
		public Selection select(AssemblyResolutionResults rr, AssemblyPatternBlock ctx)
				throws AssemblySemanticException {
			for (AssemblyResolvedPatterns res : filterCompatibleAndSort(rr, ctx)) {
				byte[] ins = res.getInstruction().getVals();
				// HACK to avoid 16-bit CALL.... TODO: Why does this happen?
				if (ins.length >= 2 && ins[0] == (byte) 0x66 && ins[1] == (byte) 0xe8) {
					System.err.println(
						"Filtered 16-bit call " + NumericUtilities.convertBytesToString(ins));
					continue;
				}
				return new Selection(res.getInstruction().fillMask(), res.getContext());
			}
			throw new AssemblySemanticException(semanticErrors);
		}
	};

}
