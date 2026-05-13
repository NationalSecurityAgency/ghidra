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
package ghidra.app.plugin.core.debug.taint;

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.location.DefaultDecompilerLocation;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.breakpoint.PlaceEmuBreakpointActionItem;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.script.AskDialog;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.util.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.property.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import sarif.SarifService;
import sarif.export.SarifWriterTask;
import sarif.export.WrappedLogicalLocation;
import sarif.managers.SarifMgr;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public class EmulatorTaintState extends AbstractTaintState {

	private DebuggerTraceManagerService traceManager;
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	private static final String SARIF_URL =
		"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
	private static final String SARIF_VERSION = "2.1.0";
	private int llIndex = 0;

	private Map<String, WrappedLogicalLocation> logicalLocations = new HashMap<>();
	//private Set<VariableRef> annotationSet = new HashSet<>();

	private Map<String, Map<Integer, String>> registerNames = new HashMap<>();
	private Object lastValue;

	public record KTV(String key, String type, String value, String displayName) {}

	public interface SetTaintAction {
		String NAME = "Set Taint";
		String DESCRIPTION = "Set taint for given varnode";
		String GROUP = DebuggerResources.GROUP_GENERAL;
		String HELP_ANCHOR = "set_taint";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.menuGroup(GROUP)
					.popupMenuGroup(GROUP)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	public EmulatorTaintState(TaintPlugin plugin) {
		super(plugin);
		ENGINE_NAME = "emulator";
		plugin.setTaintState(this);

		SetTaintAction.builder(plugin)
				.withContext(ProgramLocationActionContext.class)
				.onAction(this::setTaint)
				.buildAndInstall(plugin.getTool());
	}

	private void setTaint(ProgramLocationActionContext context) {
		Program currentProgram = plugin.getCurrentProgram();
		Address addr = context.getAddress();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function f = functionManager.getFunctionContaining(addr);
		ProgramLocation location = context.getLocation();
		int row = location.getRow();
		int offset = location.getCharOffset();

		String tokenId = null;
		if (location instanceof PcodeFieldLocation pfl) {
			List<String> pcodeStrings = pfl.getPcodeStrings();
			String test = pcodeStrings.get(row);
			int lastSpace = test.lastIndexOf(" ");
			int index = offset > lastSpace ? 1 : 0;
			Instruction inst = currentProgram.getListing().getInstructionContaining(addr);
			PcodeOp[] pcode = inst.getPcode();
			PcodeOp op = pcode[row];
			if (index >= op.getNumInputs()) {
				index--;
			}
			Varnode vn = op.getInput(index);
			tokenId = vn2oper(vn);
			sources.add(new TaintLabel(MarkType.SOURCE, f.getName(), addr, vn.getAddress()));
		}
		else if (location instanceof OperandFieldLocation ofl) {
			Address refAddress = ofl.getRefAddress();
			sources.add(new TaintLabel(MarkType.SOURCE, f.getName(), addr, refAddress));
			if (refAddress == null) {
				tokenId = ofl.getOperandRepresentation();
			}
			else {
				tokenId = addr2oper(refAddress, refAddress.getSize() / 8);
			}
		}
		else if (location instanceof DefaultDecompilerLocation ddl) {
			ClangToken token = ddl.getToken();
			plugin.toggleIcon(MarkType.SOURCE, token, false);
			return;  // taint is set via the token
		}
		else {
			AskDialog<String> dialog = new AskDialog<>("Emulator Taint",
				"Varnode address", AskDialog.STRING, lastValue);
			if (dialog.isCanceled()) {
				return;
			}
			tokenId = dialog.getValueAsString();
		}
		setTaint(MarkType.SOURCE, f, addr, tokenId);
	}

	private boolean init() {
		PluginTool tool = plugin.getTool();
		traceManager = tool.getService(DebuggerTraceManagerService.class);
		current = traceManager.getCurrent();
		return current.getTrace() != null;
	}

	/**
	 * Build the query string, save it to a file the users selects, and run the
	 * engine using the index and the query that is saved to the file.
	 */
	@Override
	public boolean queryIndex(Program program, PluginTool tool, QueryType queryType) {

		if (!init()) {
			return false;
		}

		taintOptions = plugin.getOptions();

		TraceAddressPropertyManager mgr = current.getTrace().getAddressPropertyManager();
		TracePropertyMap<String> propertyMap = mgr.getPropertyMap("Taint", String.class);
		readQueryResultsIntoDataFrame(program, propertyMap);
		return true;
	}

	@Override
	public TaintLabel toggleMark(MarkType mtype, ClangToken token) throws PcodeException {
		TaintLabel mark = super.toggleMark(mtype, token);
		setTaint(mtype, mark);
		return mark;
	}

	private void setTaint(MarkType source, Function f, Address target, String tokenId) {
		if (!init()) {
			return;
		}

		String taint = "%s = taint_arr(%s);".formatted(tokenId, tokenId);
		String sleigh = """
				%s
				emu_exec_decoded();
				""".formatted(taint);
		injectTaint(target, sleigh);
	}

	public void setTaint(MarkType type, TaintLabel mark) {
		if (!init()) {
			return;
		}

		Address target = mark.getAddress();
		String opnd = vn2oper(mark.getVnode());
		String taint = "%s = taint_arr(%s);".formatted(opnd, opnd);
		String sleigh = """
				%s
				emu_exec_decoded();
				""".formatted(taint);
		injectTaint(target, sleigh);
	}

	private void injectTaint(Address target, String sleigh) {
		PlaceEmuBreakpointActionItem item = new PlaceEmuBreakpointActionItem(current.getTrace(),
			current.getSnap(), target, 1, Set.of(TraceBreakpointKind.SW_EXECUTE),
			sleigh);
		item.execute();
	}

	public PcodeProgram rebase(Address target, PcodeProgram orig) {
		List<PcodeOp> origCode = orig.getCode();
		List<PcodeOp> code = new ArrayList<>();
		for (PcodeOp op : origCode) {
			code.add(new PcodeOp(target, op.getSeqnum().getTime(), op.getOpcode(), op.getInputs(),
				op.getOutput()));
		}
		return new PcodeProgram(orig, code);
	}

	private Writer getWriter() {
		return new StringWriter(10000);
	}

	protected void readQueryResultsIntoDataFrame(Program program,
			TracePropertyMap<String> propertyMap) {

		taintAddressSet.clear();
		taintVarnodeMap.clear();
		logicalLocations.clear();
		llIndex = 0;

		try {
			Writer baseWriter = getWriter();
			JsonWriter writer = new JsonWriter(baseWriter);
			writer.setIndent("  ");
			Gson gson = new GsonBuilder().setPrettyPrinting()
					.excludeFieldsWithoutExposeAnnotation()
					.serializeNulls()
					.disableHtmlEscaping()
					.create();
			JsonObject sarif = new JsonObject();
			JsonArray results = new JsonArray();
			JsonArray llocs = new JsonArray();
			writeSarifHeader(program, sarif, results, llocs);

			registerNames = generateRegisterMap(program);
			AddressSetView addressSetView =
				propertyMap.getAddressSetView(Lifespan.toNow(current.getSnap()));
			for (AddressRange addressRange : addressSetView) {
				TracePropertyMapSpace<String> space =
					propertyMap.getPropertyMapSpace(addressRange.getAddressSpace(), false);
				Collection<Entry<TraceAddressSnapRange, String>> entries =
					space.getEntries(Lifespan.toNow(current.getSnap()), addressRange);
				for (Entry<TraceAddressSnapRange, String> entry : entries) {
					writeResult(program.getFunctionManager(), results, llocs, entry);
				}
			}

			monitor.setMessage("Results written...exporting to JSON");
			gson.toJson(sarif, writer);
			monitor.setMessage("JSON completed");
			StringWriter w = (StringWriter) baseWriter;
			StringBuffer sb = w.getBuffer();
			SarifService sarifService = plugin.getSarifService();
			SarifMgr.getColumnKeys().put("displayName", true);
			currentQueryData = sarifService.readSarif(sb.toString());
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
		}
	}

	private Map<String, Map<Integer, String>> generateRegisterMap(Program program) {
		Language language = program.getLanguage();
		for (Register r : language.getRegisters()) {
			Map<Integer, String> sizeMap = registerNames.computeIfAbsent(r.getAddress().toString(),
				a -> new HashMap<Integer, String>());
			sizeMap.put(r.getBitLength(), r.getName());
			if (r.equals(r.getBaseRegister())) {
				sizeMap.put(0, r.getName());
			}
		}
		return registerNames;
	}

	private void writeSarifHeader(Program program, JsonObject sarif, JsonArray results,
			JsonArray llocs) {
		sarif.addProperty("$schema", SARIF_URL);
		sarif.addProperty("version", SARIF_VERSION);
		sarif.add("properties", new JsonObject());
		JsonArray runs = new JsonArray();
		sarif.add("runs", runs);
		JsonObject run = new JsonObject();
		runs.add(run);
		writeToolInfo(program, run);
		run.add("results", results);
		run.add("logicalLocations", llocs);
	}

	private void writeToolInfo(Program program, JsonObject run) {
		JsonObject tool = new JsonObject();
		run.add("tool", tool);
		JsonObject driver = new JsonObject();
		tool.add("driver", driver);
		driver.addProperty("name", "emulator");
		driver.addProperty("version", "0.1");
		driver.addProperty("informationUri", "https://github.com/NationalSecurityAgency/ghidra");

		JsonArray artifacts = new JsonArray();
		run.add("artifacts", artifacts);
		JsonObject artifact = new JsonObject();
		artifacts.add(artifact);
		JsonObject location = new JsonObject();
		artifact.add("location", location);
		location.addProperty("uri", program.getExecutablePath());

		JsonObject properties = new JsonObject();
		artifact.add("properties", properties);
		JsonObject additionalProperties = new JsonObject();
		properties.add("additionalProperties", additionalProperties);
		additionalProperties.addProperty("imageBase", program.getImageBase().toString());

		artifact.addProperty("sourceLanguage", program.getLanguageID().getIdAsString());

		JsonObject description = new JsonObject();
		artifact.add("description", description);
		description.addProperty("text", program.getMetadata().get("Compiler ID"));
	}

	private void writeResult(FunctionManager fmgr, JsonArray results, JsonArray llocs,
			Entry<TraceAddressSnapRange, String> entry) {

		try {
			SarifWriterTask task;
			SarifLogicalLocationWriter writer = new SarifLogicalLocationWriter(entry, fmgr);
			Address address = writer.getAddress();
			if (address != null) {
				taintAddressSet.add(address);
			}

			WrappedLogicalLocation wll = writer.getLogicalLocation();
			String llkey = wll.getLogicalLocation().getFullyQualfiedName();
			if (!logicalLocations.containsKey(llkey)) {
				wll.setIndex(llIndex++);
				logicalLocations.put(llkey, wll);
				task = new SarifWriterTask("taint", writer, llocs);
				task.monitoredRun(monitor);
			}

			wll = logicalLocations.get(llkey);
			String displayName = generateDisplayName(writer.getKey(), writer.getType());
			KTV ktv = new KTV(writer.getKey(), writer.getType(), writer.getValue(), displayName);
			SarifKeyValueWriter kvwriter = new SarifKeyValueWriter(ktv, wll);
			task = new SarifWriterTask("taint", kvwriter, results);
			task.monitoredRun(monitor);
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
		}
	}

	private String generateDisplayName(String key, String type) {
		String displayName = key;
		String searchKey = key.startsWith("ram@") ? key.substring(4) : key;
		if (registerNames.containsKey(searchKey)) {
			Map<Integer, String> sizeMap = registerNames.get(searchKey);
			Integer size = switch (type) {
				case "(int64)" -> 64;
				case "(int32)" -> 32;
				case "(int16)" -> 16;
				case "(int8)" -> 8;
				default -> 0;
			};
			String res = sizeMap.get(size);
			if (res == null) {
				res = sizeMap.get(0);
			}
			displayName = key.startsWith("ram@") ? "ram@" + res : res;
		}
		return displayName;
	}

	private String vn2oper(Varnode vn) {
		Address vnAddr = vn.getAddress();
		return addr2oper(vnAddr, vn.getSize());
	}

	private String addr2oper(Address addr, int size) {
		AddressSpace space = addr.getAddressSpace();
		return "*[%s]:%d 0x%s:%d".formatted(space.getName(), size,
			addr.toString(false), addr.getSize() / 8);
	}

	@Override
	public String getQueryName() {
		return "emulator";
	}

	@Override
	public GhidraScript getExportScript(ConsoleService console, boolean perFunction) {
		return null;
	}

	@Override
	public void buildQuery(List<String> paramList, String enginePath, File indexDBFile,
			String indexDirectory) {
		//UNNEEDED
	}

	@Override
	public void buildIndex(List<String> paramList, String enginePath, String factsPath,
			String indexDirectory) {
		//UNNEEDED
	}

	@Override
	protected void writeHeader(PrintWriter writer) {
		//UNNEEDED
	}

	@Override
	protected void writeRule(PrintWriter writer, TaintLabel mark, boolean isSource) {
		//UNNEEDED
	}

	@Override
	protected void writeGate(PrintWriter writer, TaintLabel mark) {
		//UNNEEDED
	}

	@Override
	protected void writeFooter(PrintWriter writer) {
		//UNNEEDED
	}

}
