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
package ghidra.app.plugin.core.decompiler.taint;

import static org.junit.Assert.*;

import java.io.File;
import java.lang.Exception;
import java.util.*;

import org.junit.*;
import org.junit.experimental.categories.Category;

import com.contrastsecurity.sarif.*;

import generic.jar.ResourceFile;
import generic.test.category.NightlyCategory;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompiler.taint.TaintState.*;
import ghidra.app.plugin.core.decompiler.taint.sarif.SarifTaintGraphRunHandler;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.Application;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.task.*;
import sarif.*;
import sarif.model.SarifDataFrame;

@Category(NightlyCategory.class)
public class DecompilerTaintTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String CTADL = "/usr/bin/ctadl";
	private static final String TMP = "~/test";

	private TestEnv env;
	private File script;
	private Program program;
	private PluginTool tool;

	private CodeBrowserPlugin browserService;
	private SarifPlugin sarifService;
	private TaintPlugin taintService;

	private DecompilerProvider decompilerProvider;

	private Iterator<ClangToken> tokenIterator;
	private Run run;
	private Address functionAddr;

	private String[] functionLabels = { "0x10021f0", "0x1003e21", "0x10021f0" };
	private Map<String, ClangToken> tokenMap = new HashMap<>();
	//@formatter:off
	private String[][] testTargets = {{
			"param_1", "param_1:010021fc", 
			"AVar1", "AVar1:01002292", 
			"local_50", "local_50:0100226a","local_50:01002270", "local_50:01002283",
			"hCursor:01002270",
			"_DAT_01005b28:01002243", "_DAT_01005b28:01002270",
			"DAT_01005b30:010021fc", "DAT_01005b30:01002243", "DAT_01005b30:0100226a",
			"DAT_01005b24:0100230f", "DAT_01005b24:01002365",
		}, {
			"pHVar1", "pHVar1:01003e36", "pHVar1:01003f8d",
		}, {
			"pHVar1", "pHVar1:01003e36", "pHVar1:01003f8d",
		}};
	private int testIndex = 0;
	private int[] testSizes = {
			11,11, 11,10,
			3,3, 3,3,
			20,3, 20,2, 20,2, 20,0, 
			2,2, 
			4,4, 4,4,
			8,8, 8,7, 8,7,
			9,9, 9,4,
			
			21,21, 21,7, 11,0,
			
			11,11, 11,0, 11,11,
		};
	//@formatter:on

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		ResourceFile resourceFile =
			Application.getModuleFile("DecompilerDependent",
				"ghidra_scripts/ExportPCodeForCTADL.java");
		script = resourceFile.getFile(true);

		program = env.getProgram("Winmine__XP.exe.gzf");
		tool = env.launchDefaultTool(program);
		tool.addPlugin(DecompilePlugin.class.getName());
		tool.addPlugin(SarifPlugin.class.getName());
		tool.addPlugin(TaintPlugin.class.getName());
		showProvider(tool, "Decompiler");

		ToolOptions options = tool.getOptions("Decompiler");
		options.setString(TaintOptions.OP_KEY_TAINT_ENGINE_PATH, CTADL);
		options.setString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, TMP);
		options.setString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, TMP);

		initServices();
		initDatabase();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	// NB: This test is VERY slow. I do not recommend running it on a regular basis.
	//  Each of the 22 paired examples above takes close to a minute to run, so...
	@Ignore
	@Test
	public void testWinmine() throws Exception {
		int nf = 0;
		for (String f : functionLabels) {
			decompilerProvider = taintService.getDecompilerProvider();
			decompilerProvider.goTo(program,
				new ProgramLocation(program, program.getMinAddress().getAddress(f)));
			goTo(program, f);
			waitForSwing();
			//System.err.println("TESTING: "+browserService.getCurrentLocation());

			try {
				functionAddr = program.getMinAddress().getAddress(f);
			}
			catch (AddressFormatException e) {
				e.printStackTrace();
			}

			for (int i = 0; i < testTargets[nf].length; i++) {
				ClangToken token = tokenMap.get(testTargets[nf][i]);
				if (token != null) {
					processToken(token, true);
					processToken(token, false);
				}
				else {
					System.err.println("NULL for " + testTargets[nf][i]);
				}
			}
			nf++;
		}
	}

	private void processToken(ClangToken token, boolean bySymbol) throws Exception {
		TaintState taintState = taintService.getTaintState();
		taintState.clearMarkers();
		taintService.clearIcons();
		taintService.clearTaint();
		taintService.toggleIcon(MarkType.SOURCE, token, bySymbol);

		taintState.clearData();
		taintState.queryIndex(program, tool, QueryType.SRCSINK);
		SarifSchema210 data;
		while ((data = taintState.getData()) == null) {
			Thread.sleep(100);
		}
		SarifDataFrame df = new SarifDataFrame(data, sarifService.getController(), false);

		this.run = taintState.getData().getRuns().get(0);
		Map<Address, Set<TaintQueryResult>> map = new HashMap<>();
		for (Map<String, Object> result : df.getTableResults()) {
			processResult(map, result);
		}
		taintService.setVarnodeMap(map, true, TaskType.SET_TAINT);
		validateResult(token, map);
	}

	private void processResult(Map<Address, Set<TaintQueryResult>> map, Map<String, Object> result)
			throws Exception {
		String kind = (String) result.get("kind");
		if (kind.equals("member")) {
			getTaintedInstruction(map, result);
		}
		if (kind.equals("variable")) {
			getTaintedVariable(map, result);
		}
	}

	private void validateResult(ClangToken token, Map<Address, Set<TaintQueryResult>> map) {
		Set<TaintQueryResult> set = map.get(functionAddr);
		//System.err.println("VALIDATE: "+functionAddr);
		if (set != null) {
			int sz = taintService.getProvider().getTokenCount();
			//assertEquals(testSizes[testIndex], sz);
			System.err.println(testSizes[testIndex] + " vs " + sz);
		}
		//else {
		//	System.err.println("NULL for "+functionAddr);
		//}
		testIndex++;
	}

	private void getTaintedVariable(Map<Address, Set<TaintQueryResult>> map,
			Map<String, Object> result) {
		Address faddr = (Address) result.get("entry");
		Set<TaintQueryResult> vset = getSet(map, faddr);
		vset.add(new TaintQueryResult(result));
	}

	private void getTaintedInstruction(Map<Address, Set<TaintQueryResult>> map,
			Map<String, Object> result) {
		Address faddr = (Address) result.get("entry");
		String fqname = (String) result.get("location");
		Set<TaintQueryResult> vset = getSet(map, faddr);
		Set<String> edgeIds = SarifUtils.getEdgeSet(fqname);
		if (edgeIds != null) {
			for (String edgeId : edgeIds) {
				String srcId = SarifUtils.getEdgeSource(edgeId);
				LogicalLocation[] srcNodes = SarifUtils.getNodeLocs(srcId);
				for (LogicalLocation lloc : srcNodes) {
					vset.add(new TaintQueryResult(result, run, lloc));
				}
				String dstId = SarifUtils.getEdgeDest(edgeId);
				LogicalLocation[] dstNodes = SarifUtils.getNodeLocs(dstId);
				for (LogicalLocation lloc : dstNodes) {
					vset.add(new TaintQueryResult(result, run, lloc));
				}
			}
		}
	}

	private Set<TaintQueryResult> getSet(Map<Address, Set<TaintQueryResult>> map, Address faddr) {
		Set<TaintQueryResult> vset = map.get(faddr);
		if (vset == null) {
			vset = new HashSet<TaintQueryResult>();
			map.put(faddr, vset);
		}
		return vset;
	}

	private void initServices() {
		CodeViewerService viewer = tool.getService(CodeViewerService.class);
		if (viewer instanceof CodeBrowserPlugin cb) {
			this.browserService = cb;
		}
		SarifService sarif = tool.getService(SarifService.class);
		if (sarif instanceof SarifPlugin sp) {
			this.sarifService = sp;
		}
		TaintService taint = tool.getService(TaintService.class);
		if (taint instanceof TaintPlugin tp) {
			this.taintService = tp;
		}
		sarifService.getController().setDefaultGraphHander(SarifTaintGraphRunHandler.class);
	}

	private void initDatabase() throws Exception {
		ScriptTaskListener scriptId = env.runScript(script);
		waitForScriptCompletion(scriptId, 65000);
		program.flushEvents();
		waitForSwing();

		CreateTargetIndexTask indexTask =
			new CreateTargetIndexTask(taintService, taintService.getCurrentProgram());
		TaskBusyListener listener = new TaskBusyListener();
		indexTask.addTaskListener(listener);
		new TaskLauncher(indexTask, tool.getActiveWindow());
		waitForBusyTool(tool);
//		while (listener.executing) {
//			Thread.sleep(100);
//		}

		for (String f : functionLabels) {
			decompilerProvider = taintService.getDecompilerProvider();
			decompilerProvider.goTo(program,
				new ProgramLocation(program, program.getMinAddress().getAddress(f)));
			goTo(program, f);
			waitForSwing();
			//System.err.println("INIT: "+browserService.getCurrentLocation());

			ClangToken tokenAtCursor = decompilerProvider.getDecompilerPanel().getTokenAtCursor();
			ClangFunction clangFunction = tokenAtCursor.getClangFunction();
			tokenIterator = clangFunction.tokenIterator(true);
			while (tokenIterator.hasNext()) {
				ClangToken next = tokenIterator.next();
				if (next instanceof ClangVariableToken ||
					next instanceof ClangFieldToken ||
					next instanceof ClangFuncNameToken) {
					if (next instanceof ClangVariableToken vtoken) {
						Varnode vn = vtoken.getVarnode();
						if (vn != null) {
							HighVariable high = vn.getHigh();
							if (high instanceof HighConstant) {
								continue;
							}
						}
					}
					String key = next.getText();
					if (next.getPcodeOp() != null) {
						key += ":" + next.getPcodeOp().getSeqnum().getTarget();
					}
					tokenMap.put(key, next);
				}
			}
		}
	}

	private void goTo(Program prog, String addr)  {
		runSwing(() -> {
			try {
				Address min = prog.getMinAddress();
				functionAddr = min.getAddress(addr);
				browserService.getNavigatable()
						.goTo(prog, new ProgramLocation(prog, functionAddr));
			}
			catch (AddressFormatException e) {
				e.printStackTrace();
			}
		});
	}

	private class TaskBusyListener implements TaskListener {

		public boolean executing = true;

		TaskBusyListener() {
			executing = true;
		}

		@Override
		public void taskCompleted(Task t) {
			executing = false;
		}

		@Override
		public void taskCancelled(Task t) {
			executing = false;
		}
	}
}
