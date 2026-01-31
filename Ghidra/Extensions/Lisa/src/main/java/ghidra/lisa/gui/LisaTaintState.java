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
package ghidra.lisa.gui;

import java.io.*;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.plugin.core.decompiler.absint.AbstractInterpretationService;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lisa.pcode.analyses.*;
import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.dataflow.*;
import it.unive.lisa.analysis.nonrelational.inference.InferenceSystem;
import it.unive.lisa.analysis.nonrelational.value.TypeEnvironment;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.value.ValueDomain;
import it.unive.lisa.outputs.serializableGraph.*;
import it.unive.lisa.program.annotations.Annotation;
import it.unive.lisa.program.annotations.Annotations;
import it.unive.lisa.program.cfg.statement.*;
import it.unive.lisa.symbolic.value.Identifier;
import it.unive.lisa.util.representation.*;
import sarif.SarifService;
import sarif.export.SarifWriterTask;
import sarif.export.WrappedLogicalLocation;
import sarif.managers.SarifMgr;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public class LisaTaintState extends AbstractTaintState {

	private LisaPlugin lisa;
	private static final String SARIF_URL =
		"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
	private static final String SARIF_VERSION = "2.1.0";
	private Map<String, WrappedLogicalLocation> logicalLocations = new HashMap<>();
	private Set<VariableRef> annotationSet = new HashSet<>();
	private int llIndex = 0;
	private boolean suppressTop = true;
	private boolean suppressUnique = true;

	private Map<String, Map<Integer, String>> registerNames = new HashMap<>();

	public record KTV(String key, String type, String value, String displayName) {}

	public LisaTaintState(TaintPlugin plugin) {
		super(plugin);
		ENGINE_NAME = "lisa";
	}

	private boolean init() {
		if (lisa == null) {
			AbstractInterpretationService service =
				plugin.getTool().getService(AbstractInterpretationService.class);
			if (service instanceof LisaPlugin lisaService) {
				this.lisa = lisaService;
			}
			else {
				return false;
			}
		}
		return true;
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

		for (TaintLabel mark : getTaintLabels(MarkType.SOURCE)) {
			if (mark.isActive()) {
				Function f = mark.getHighFunction().getFunction();
				Address target = mark.getAddress();
				String tokenId = mark.getVarnodeAddress().toString();
				setTaint(MarkType.SOURCE, f, target, tokenId);
			}
		}
		for (TaintLabel mark : getTaintLabels(MarkType.SINK)) {
			if (mark.isActive()) {
				Function f = mark.getHighFunction().getFunction();
				Address target = mark.getAddress();
				String tokenId = mark.getVarnodeAddress().toString();
				setTaint(MarkType.SINK, f, target, tokenId);
			}
		}
		for (TaintLabel mark : getTaintLabels(MarkType.GATE)) {
			if (mark.isActive()) {
				Function f = mark.getHighFunction().getFunction();
				Address target = mark.getAddress();
				String tokenId = mark.getVarnodeAddress().toString();
				setTaint(MarkType.GATE, f, target, tokenId);
			}
		}
		Map<Function, Collection<?>> results = lisa.performAnalysis(monitor);
		if (results != null) {
			readQueryResultsIntoDataFrame(program, results);
		}
		return results != null;
	}

	public void clearAnnotations() {
		for (VariableRef var : annotationSet) {
			Collection<Annotation> annotations = var.getAnnotations().getAnnotations();
			annotations.clear();
		}
	}

	public void setTaint(MarkType type, Function f, Address target, String tokenId) {
		if (!init()) {
			return;
		}

		for (Statement st : lisa.getStatements(f)) {
			Address stAddr = null;
			if (st.getLocation() instanceof PcodeLocation loc) {
				stAddr = loc.getAddress();
			}
			else if (st.getLocation() instanceof InstLocation loc) {
				stAddr = loc.getAddress();
			}
			if (stAddr.getOffset() >= target.getOffset()) {
				if (st instanceof Expression x) {
					if (markExpression(type, x, tokenId, stAddr)) {
						break;
					}
				}
			}
		}
	}

	private boolean markExpression(MarkType type, Expression x, String tokenId, Address target) {
		boolean ret = false;
		if (x instanceof VariableRef vref) {
			String id = vref.toString();
			if (id.equals(tokenId)) {
				Annotations annotations = vref.getAnnotations();
				Annotation ann = type == MarkType.SOURCE ? new Annotation("Tainted@" + target)
						: new Annotation("Clean@" + target);
				annotations.addAnnotation(ann);
				annotationSet.add(vref);
				return true;
			}
		}
		if (x instanceof NaryExpression nx) {
			Expression[] subx = nx.getSubExpressions();
			for (Expression sx : subx) {
				ret |= markExpression(type, sx, tokenId, target);
			}
		}
		return ret;
	}

	private Writer getWriter() {
		return new StringWriter(10000);
	}

	protected void readQueryResultsIntoDataFrame(Program program,
			Map<Function, Collection<?>> res) {

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

			LisaOptions options = lisa.getOptions();
			suppressTop = !options.isShowTop();
			suppressUnique = !options.isShowUnique();

			registerNames = generateRegisterMap(program);
			for (Function f : res.keySet()) {
				Collection<?> c = res.get(f);
				Iterator<?> iteratorC = c.iterator();
				while (iteratorC.hasNext() && !monitor.isCancelled()) {
					Object next = iteratorC.next();
					if (next instanceof AnalyzedCFG<?> acfg) {
						writeResults(program, f, results, llocs, acfg);
					}
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
		driver.addProperty("name", "lisa");
		driver.addProperty("version", "0.1");
		driver.addProperty("informationUri", "https://github.com/lisa-analyzer");

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

	private void writeResults(Program program, Function f, JsonArray results, JsonArray llocs,
			AnalyzedCFG<?> acfg) {
		try {
			for (Statement st : lisa.getStatements(f)) {
				AbstractState<?> state =
					lisa.getOptions().isPostState() ? acfg.getAnalysisStateAfter(st).getState()
							: acfg.getAnalysisStateBefore(st).getState();
				if (state instanceof SimpleAbstractState sas) {
					processSimpleState(results, llocs, f, st, sas);
				}
				if (monitor.isCancelled()) {
					break;
				}
			}
		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	@SuppressWarnings("rawtypes")
	private void processSimpleState(JsonArray results, JsonArray llocs, Function f, Statement st,
			SimpleAbstractState sas) {
		Map<Identifier, ?> tfunction = getTypeMap(sas);

		ValueDomain valueState = sas.getValueState();
		if (valueState instanceof PcodeStability stab) {
			valueState = stab.getTrends();
		}
		if (valueState instanceof PcodePentagon pent) {
			valueState = pent.getIntervals();
		}
		if (valueState instanceof ValueEnvironment ve) {
			@SuppressWarnings("unchecked")
			Map<Identifier, ?> vfunction = ve.function;
			if (vfunction == null) {
				return;
			}
			for (Object key : vfunction.keySet()) {
				if (vfunction.get(key) instanceof StructuredObject vso) {
					KTV ktv = repToStrings(key.toString(), vso.representation(), tfunction);
					processKeyValue(results, llocs, f, st, ktv);
				}
			}
		}
		if (valueState instanceof InferenceSystem is) {
			@SuppressWarnings("unchecked")
			Map<Identifier, ?> vfunction = is.function;
			if (vfunction == null) {
				return;
			}
			for (Object key : vfunction.keySet()) {
				if (vfunction.get(key) instanceof StructuredObject vso) {
					KTV ktv = repToStrings(key.toString(), vso.representation(), tfunction);
					processKeyValue(results, llocs, f, st, ktv);
				}
			}
		}
		if (valueState instanceof DefiniteDataflowDomain ddd) {
			for (Object object : ddd.getDataflowElements()) {
				StructuredRepresentation rep = null;
				if (object instanceof PcodeDataflowConstantPropagation cp) {
					rep = cp.representation();
				}
				if (object instanceof AvailableExpressions ae) {
					rep = ae.representation();
				}
				KTV ktv = repToStrings(null, rep, tfunction);
				processKeyValue(results, llocs, f, st, ktv);
			}
		}
		if (valueState instanceof PossibleDataflowDomain pdd) {
			for (Object object : pdd.getDataflowElements()) {
				StructuredRepresentation rep = null;
				if (object instanceof ReachingDefinitions rd) {
					rep = rd.representation();
				}
				if (object instanceof Liveness lv) {
					rep = lv.representation();
				}
				KTV ktv = repToStrings(null, rep, tfunction);
				processKeyValue(results, llocs, f, st, ktv);
			}
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private Map<Identifier, ?> getTypeMap(SimpleAbstractState sas) {
		if (sas.getTypeState() instanceof TypeEnvironment te) {
			return te.function;
		}
		return null;
	}

	private KTV repToStrings(String key, StructuredRepresentation rep, Map<Identifier, ?> typeMap) {
		String val = "";
		if (rep instanceof StringRepresentation srep) {
			String[] split = srep.toString().split(" ");
			if (key == null) {
				key = split.length == 2 ? split[1] : split[0];
			}
			val = srep.toString();
		}
		if (rep instanceof SetRepresentation srep) {
			SerializableValue sval = srep.toSerializableValue();
			if (sval instanceof SerializableArray sarr) {
				List<SerializableValue> elements = sarr.getElements();
				val = ((SerializableString) elements.get(0)).getValue();
				if (elements.size() > 1) {
					Msg.error(this, "Unexpected result: " + sval);
				}
			}
		}
		if (rep instanceof ListRepresentation lrep) {
			SerializableValue sval = lrep.toSerializableValue();
			if (sval instanceof SerializableArray sarr) {
				List<SerializableValue> elements = sarr.getElements();
				if (key == null) {
					key = ((SerializableString) elements.get(0)).getValue();
				}
				val = ((SerializableString) elements.get(1)).getValue();
				if (elements.size() > 2) {
					Msg.error(this, "Unexpected result: " + sval);
				}
			}
		}
		if (StringUtils.isNumeric(val)) {
			val = Long.toHexString(Long.parseLong(val));
		}
		String type = "";
		for (Identifier k : typeMap.keySet()) {
			if (k.toString().equals(key)) {
				type = typeMap.get(k).toString();
				break;
			}
		}
		String displayName = generateDisplayName(key, type);
		return new KTV(key, type, val, displayName);
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

	private void processKeyValue(JsonArray results, JsonArray llocs, Function f, Statement st,
			KTV ktv) {
		boolean isTop = ktv.value.contains(LisaOptions.getTopValue());
		boolean isUnique = ktv.key.contains("unique:");
		if (!(isTop && suppressTop) && !(isUnique && suppressUnique)) {
			writeResult(ktv, f, st, llocs, results);
			if (st.getLocation() instanceof PcodeLocation ploc) {
				taintAddressSet.add(ploc.getAddress());
			}
			if (st.getLocation() instanceof InstLocation iloc) {
				taintAddressSet.add(iloc.getAddress());
			}
		}
	}

	private void writeResult(KTV ktv, Function f, Statement st, JsonArray llocs,
			JsonArray results) {

		try {
			SarifWriterTask task;
			SarifLogicalLocationWriter locWriter = new SarifLogicalLocationWriter(ktv.key, f, st);
			WrappedLogicalLocation wll = locWriter.getLogicalLocation();
			String llkey = wll.getLogicalLocation().getFullyQualfiedName();
			if (!logicalLocations.containsKey(llkey)) {
				wll.setIndex(llIndex++);
				logicalLocations.put(llkey, wll);
				task = new SarifWriterTask(lisa.valueOption.toString(), locWriter, llocs);
				task.monitoredRun(monitor);
			}

			wll = logicalLocations.get(llkey);
			SarifKeyValueWriter writer = new SarifKeyValueWriter(ktv, wll);
			task = new SarifWriterTask(lisa.valueOption.toString(), writer, results);
			task.monitoredRun(monitor);
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage());
		}
	}

	@Override
	public String getQueryName() {
		return lisa.getActiveQueryName();
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

	public void setSuppressTop(boolean suppressTop) {
		this.suppressTop = suppressTop;
	}

	public void setSuppressUnique(boolean suppressUnique) {
		this.suppressUnique = suppressUnique;
	}

}
