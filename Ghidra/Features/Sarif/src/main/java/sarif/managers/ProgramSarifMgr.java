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
package sarif.managers;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.SarifSchema210;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MzLoader;
import ghidra.app.util.opinion.NeLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.Application;
import ghidra.program.database.module.TreeManager;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import sarif.SarifController;
import sarif.SarifProgramOptions;
import sarif.export.SarifObject;
import sarif.io.SarifGsonIO;
import sarif.io.SarifIO;
import sarif.model.SarifDataFrame;

/**
 * The manager responsible for reading and writing a program in SARIF.
 */
public class ProgramSarifMgr {

	private static final String SARIF_URL = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";
	private static final String SARIF_VERSION = "2.1.0";
	private static final int N_MANAGERS = 16;

	private ProgramInfo info;
	private File file;
	private File tempFile;
	private String fileContents;
	private SarifSchema210 sarif;
	private SarifController controller;
	private SarifDataFrame df;
	private SarifMgr[] mgrs;
	private Boolean[] opts;
	private Program program;
	private SarifProgramOptions options;
	private Map<String, Boolean> keys = new HashMap<>();
	private Writer baseWriter;

	/**
	 * Constructs a new program SARIF manager for applying results to an existing
	 * program - used by the SarifPlugin
	 */
	public ProgramSarifMgr(Program program) {
		this.program = program;
		options = new SarifProgramOptions();
		addManagers();
	}

	/**
	 * Constructs a new program SARIF manager using the specified file for export.
	 * The file should be an SARIF file.
	 * 
	 * @param file the SARIF file
	 */
	public ProgramSarifMgr(Program program, File file) {
		this(program);
		this.file = file;
	}

	/**
	 * Constructs a new program SARIF manager using the specified file as import for
	 * creating a new program object
	 *
	 * @param bp byte provider
	 */
	public ProgramSarifMgr(ByteProvider bp) {
		options = new SarifProgramOptions();
		this.file = (bp.getFSRL() != null && bp.getFSRL().getNestingDepth() == 1) ? new File(bp.getFSRL().getPath())
				: bp.getFile();
	}

	/**
	 * Returns the program info from the underlying file. T``his method does not
	 * make sense to invoke if a write is being performed to a new file.
	 * 
	 * @return the program info
	 * @throws IOException if an I/O error occurs
	 */
	public ProgramInfo getProgramInfo() throws IOException {
		if (info != null) {
			return info;
		}

		info = new ProgramInfo();

		SarifIO io = new SarifGsonIO();
		sarif = getSarif(io);
		controller = new SarifController(this);
		df = new SarifDataFrame(sarif, controller, true);
		List<Run> runs = sarif.getRuns();
		Set<Artifact> artifacts = runs.get(0).getArtifacts();
		Iterator<Artifact> iterator = artifacts.iterator();
		while(iterator.hasNext()) {
			Artifact next = iterator.next();
			Map<String, Object> props = next.getProperties().getAdditionalProperties();
			info.imageBase = (String) props.get("imageBase");
		}

		info.programName = "";
		info.exePath = "";
		info.exeFormat = "";
		info.user = "";
		info.setTool("");
		info.timestamp = "";
		info.version = "";
		info.languageID = new LanguageID(df.getSourceLanguage());
		info.compilerSpecID = new CompilerSpecID(df.getCompiler());
		info.processorName = "";
		info.family = "";
		info.addressModel = "";
		info.endian = "";

		return info;
	}

	private SarifSchema210 getSarif(SarifIO io) throws IOException {
		return file != null ? io.readSarif(file) : io.readSarif(getFileContents());
	}

	private Writer getWriter() throws IOException {
		return file != null ? new FileWriter(file) : new StringWriter(1000);
	}


	public void addManagers() {
		int mgrCount = 0;
		MessageLog log = new MessageLog();
		mgrs = new SarifMgr[N_MANAGERS+1];
		opts = new Boolean[N_MANAGERS+1];
		mgrs[mgrCount] = new DataTypesSarifMgr(program, log);
		opts[mgrCount++] = options.isData();
		mgrs[mgrCount] = new MemoryMapSarifMgr(this, program, log);
		opts[mgrCount++] = options.isMemoryBlocks();
		mgrs[mgrCount] = new RegisterValuesSarifMgr(program, log);
		opts[mgrCount++] = options.isRegisters();
		mgrs[mgrCount] = new CodeSarifMgr(program, log);
		opts[mgrCount++] = options.isInstructions();
		mgrs[mgrCount] = new DefinedDataSarifMgr(program, log);
		opts[mgrCount++] = options.isData();
		mgrs[mgrCount] = new EquatesSarifMgr(program, log);
		opts[mgrCount++] = options.isEquates();
		mgrs[mgrCount] = new CommentsSarifMgr(program, log);
		opts[mgrCount++] = options.isComments();
		mgrs[mgrCount] = new PropertiesSarifMgr(program, log);
		opts[mgrCount++] = options.isProperties();
		mgrs[mgrCount] = new BookmarksSarifMgr(program, log);
		opts[mgrCount++] = options.isBookmarks();
		mgrs[mgrCount] = new ProgramTreeSarifMgr(program, log);
		opts[mgrCount++] = options.isTrees();
		mgrs[mgrCount] = new ExtEntryPointSarifMgr(program, log);
		opts[mgrCount++] = options.isEntryPoints();
		mgrs[mgrCount] = new RelocationTableSarifMgr(program, log);
		opts[mgrCount++] = options.isRelocationTable();
		mgrs[mgrCount] = new SymbolTableSarifMgr(program, log, true);
		opts[mgrCount++] = options.isSymbols();
		mgrs[mgrCount] = new ExternalLibSarifMgr(program, log);
		opts[mgrCount++] = options.isExternalLibraries();
		mgrs[mgrCount] = new FunctionsSarifMgr(program, log);
		opts[mgrCount++] = options.isFunctions();
		mgrs[mgrCount] = new SymbolTableSarifMgr(program, log, false);
		opts[mgrCount++] = options.isSymbols();
		mgrs[mgrCount] = new MarkupSarifMgr(program, log);
		opts[mgrCount++] = options.isReferences();
		assert (mgrCount == N_MANAGERS+1);

		Map<String, Boolean> columnKeys = SarifMgr.getColumnKeys();
		for (String k : columnKeys.keySet()) {
			keys.put(k, columnKeys.get(k));
		}
	}

	public Map<String, Boolean> getKeys() {
		return keys;
	}

	/**
	 * Reads from the underlying SARIF file and populates the specified program.
	 * 
	 * @param program the program to load the SARIF into
	 * @param monitor the task monitor
	 * @param options the SARIF options, which features to load and to ignore
	 * @return the message log containing any warning/error messages
	 * @throws SAXException           if an SARIF error occurs
	 * @throws IOException            if an I/O occurs
	 * @throws AddressFormatException if an invalid address is specified in the
	 *                                SARIF
	 */
	public MessageLog read(Program program, TaskMonitor monitor)
			throws IOException, AddressFormatException {

		if (mgrs == null || program != this.program) {
			this.program = program;
			addManagers();
		}
		if (df == null) {
			SarifIO io = new SarifGsonIO();
			sarif = getSarif(io);
			controller = new SarifController(this);
		}
		controller.setProgram(program);
		df = new SarifDataFrame(sarif, controller, false);

		Map<String, List<Map<String, Object>>> tableResults = getDataFrame().getTableResultsAsMap();

		readResults(monitor, options, tableResults);

		createDefaultTree(program, options);

		// if instructions were imported, then remove the "needs analyzed" property
		if (options.isInstructions()) {
			GhidraProgramUtilities.markProgramAnalyzed(program);
		}

		return null;
	}

	public void readResults(TaskMonitor monitor, SarifProgramOptions options,
			Map<String, List<Map<String, Object>>> tableResults) throws IOException {
		try {
			for (int i = 0; i < mgrs.length; i++) {
				if (opts[i]) {
					List<Map<String, Object>> list = tableResults.get(mgrs[i].getKey());
					mgrs[i].readResults(list, options, monitor);
				}
			}
		} catch (Exception e) {
			throw new IOException("SARIF Read Cancelled");
		}

	}

	/**
	 * Converts from a generic format name to standard Ghidra names;
	 *
	 * @param name the generic format name
	 * @return the equivalent Ghidra name
	 */
	public static String getStandardName(String name) {
		if (name == null) {
			return "Unknown";
		} else if (name.toLowerCase().indexOf("portable executable") >= 0 && name.toLowerCase().indexOf("(pe)") >= 0) {
			return PeLoader.PE_NAME;
		} else if (name.toLowerCase().indexOf("(elf)") != -1) {
			return ElfLoader.ELF_NAME;
		} else if (name.toLowerCase().indexOf("dos executable") >= 0) {
			return MzLoader.MZ_NAME;
		} else if (name.toLowerCase().indexOf("new executable") >= 0) {
			return NeLoader.NE_NAME;
		}
		return name;
	}

	private void createDefaultTree(Program program, SarifProgramOptions options) {

		if (options.isAddToProgram()) {
			return;
		}

		Listing listing = program.getListing();
		if (listing.getTreeNames().length == 0) {
			try {
				listing.createRootModule(TreeManager.DEFAULT_TREE_NAME);
			} catch (DuplicateNameException e) {
				// shouldn't happen since we checked the tree names above
				Msg.debug(this, "Unable to create default module", e);
			}
		}

	}

	/**
	 * Writes the specified program in SARIF into the underlying file.
	 * 
	 * @param program the program to write into SARIF
	 * @param addrSet an address set to limit areas of program that written, or null
	 *                for entire program
	 * @param monitor the task monitor
	 * @param options the SARIF options to limit what is and is not written out
	 * @return the message log containing any warning/error messages
	 * @throws IOException        if an I/O occurs
	 * @throws CancelledException if the user cancels the read
	 */
	public MessageLog write(Program program, AddressSetView addrSet, TaskMonitor monitor, SarifProgramOptions options)
			throws IOException, CancelledException {

		MessageLog log = new MessageLog();

		baseWriter = getWriter();
		JsonWriter writer = new JsonWriter(getBaseWriter());
		writer.setIndent("  ");
		Gson gson = new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().serializeNulls()
				.disableHtmlEscaping().create();
		try {
			if (SarifObject.SARIF) {
				JsonObject sarif = new JsonObject();
				JsonArray results = new JsonArray();
				writeSarifHeader(program, sarif, results);
				writeResults(program, addrSet, results, monitor, log, options);
			    monitor.setMessage("Results written...exporting to JSON");
				gson.toJson(sarif, writer);
			    monitor.setMessage("JSON completed");
			} else {
				JsonObject json = new JsonObject();
				json.addProperty("name", program.getDomainFile().getName());
				json.addProperty("exe_path", program.getExecutablePath());
				json.addProperty("exe_format", program.getExecutableFormat());
				json.addProperty("image_base", program.getImageBase().toString());
				writeInfoSource(json, monitor);
				writeProcessor(program, json, monitor);
				JsonArray results = new JsonArray();
				json.add("results", results);
				writeResults(program, addrSet, results, monitor, log, options);
			    monitor.setMessage("Results written...exporting to JSON");
				gson.toJson(json, writer);
			    monitor.setMessage("JSON completed");
			}
		} finally {
			writer.flush();
			writer.close();
		}

		return log;
	}

	private void writeSarifHeader(Program program, JsonObject sarif, JsonArray results) {
		sarif.addProperty("$schema", SARIF_URL);
		sarif.addProperty("version", SARIF_VERSION);
		sarif.add("properties", new JsonObject());
		JsonArray runs = new JsonArray();
		sarif.add("runs", runs);
		JsonObject run = new JsonObject();
		runs.add(run);
		writeToolInfo(program, run);
		run.add("results", results);
	}

	private void writeToolInfo(Program program, JsonObject run) {
		JsonObject tool = new JsonObject();
		run.add("tool", tool);
		JsonObject driver = new JsonObject();
		tool.add("driver", driver);
		driver.addProperty("name", Application.getName());
		driver.addProperty("version", Application.getApplicationVersion());
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
		// JsonObject message = new JsonObject();
		// description.add("message", message);
		description.addProperty("text", program.getMetadata().get("Compiler ID"));
	}

	private void writeResults(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		writeCodeBlocks(program, addrSet, results, monitor, log, options);
		writeComments(program, addrSet, results, monitor, log, options);
		writeDataTypes(program, addrSet, results, monitor, log, options);
		writeMemoryMap(program, addrSet, results, monitor, log, options);
		writeRegisters(program, addrSet, results, monitor, log, options);
		writeDefinedData(program, addrSet, results, monitor, log, options);
		writeEquates(program, addrSet, results, monitor, log, options);
		writeProperties(program, addrSet, results, monitor, log, options);
		writeBookmarks(program, addrSet, results, monitor, log, options);
		writeTrees(program, addrSet, results, monitor, log, options); 
		writeEntryPoints(program, addrSet, results, monitor, log, options);
		writeRelocations(program, addrSet, results, monitor, log, options);
		writeFunctions(program, addrSet, results, monitor, log, options);
		writeSymbols(program, addrSet, results, monitor, log, options);
		writeReferences(program, addrSet, results, monitor, log, options);
		writeExtLibraries(program, addrSet, results, monitor, log, options);
	}

	private void writeCodeBlocks(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isInstructions()) {
			CodeSarifMgr mgr = new CodeSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeComments(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isComments()) {
			CommentsSarifMgr mgr = new CommentsSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeDataTypes(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isData()) {
			DataTypesSarifMgr mgr = new DataTypesSarifMgr(program, log);
			mgr.write(results, monitor);
		}
	}

	private void writeMemoryMap(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isMemoryBlocks()) {
			MemoryMapSarifMgr mgr = new MemoryMapSarifMgr(this, program, log);
			String path = file != null ? file.getAbsolutePath() : tempFile.getAbsolutePath();
			mgr.write(results, addrSet, monitor, options.isMemoryContents(), path);
		}
	}

	private void writeEquates(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isEquates()) {
			EquatesSarifMgr mgr = new EquatesSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeProperties(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isProperties()) {
			PropertiesSarifMgr mgr = new PropertiesSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeBookmarks(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isBookmarks()) {
			BookmarksSarifMgr mgr = new BookmarksSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeRegisters(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isRegisters()) {
			RegisterValuesSarifMgr mgr = new RegisterValuesSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeTrees(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isTrees()) {
			ProgramTreeSarifMgr mgr = new ProgramTreeSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeEntryPoints(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isEntryPoints()) {
			ExtEntryPointSarifMgr mgr = new ExtEntryPointSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeRelocations(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isRelocationTable()) {
			RelocationTableSarifMgr mgr = new RelocationTableSarifMgr(program, log);
			mgr.write(results, monitor);
		}
	}

	private void writeDefinedData(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isData()) {
			DefinedDataSarifMgr mgr = new DefinedDataSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeFunctions(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isFunctions()) {
			FunctionsSarifMgr mgr = new FunctionsSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeSymbols(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isSymbols()) {
			SymbolTableSarifMgr mgr = new SymbolTableSarifMgr(program, log, true);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeReferences(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isReferences()) {
			MarkupSarifMgr mgr = new MarkupSarifMgr(program, log);
			mgr.write(results, addrSet, monitor);
		}
	}

	private void writeExtLibraries(Program program, AddressSetView addrSet, JsonArray results, TaskMonitor monitor,
			MessageLog log, SarifProgramOptions options) throws IOException, CancelledException {
		if (options.isExternalLibraries()) {
			ExternalLibSarifMgr mgr = new ExternalLibSarifMgr(program, log);
			mgr.write(results, monitor);
		}
	}

	private void writeInfoSource(JsonObject json, TaskMonitor monitor) {
		monitor.setMessage("Writing INFO SOURCE ...");

		JsonObject attrs = new JsonObject();
		String user = SystemUtilities.getUserName();
		if (user != null) {
			attrs.addProperty("USER", user);
		}
		attrs.addProperty("TOOL", "Ghidra " + Application.getApplicationVersion());
		attrs.addProperty("TIMESTAMP", new Date().toString());

		json.add("INFO_SOURCE", attrs);
	}

	private void writeProcessor(Program program, JsonObject json, TaskMonitor monitor) {
		monitor.setMessage("Writing PROCESSOR ...");

		JsonObject attrs = new JsonObject();
		Language language = program.getLanguage();
		CompilerSpec compilerSpec = program.getCompilerSpec();

		attrs.addProperty("NAME", language.getProcessor().toString());
		attrs.addProperty("LANGUAGE_PROVIDER",
				language.getLanguageID().getIdAsString() + ":" + compilerSpec.getCompilerSpecID().getIdAsString());
		attrs.addProperty("ENDIAN", language.isBigEndian() ? "big" : "little");

		json.add("PROCESSOR", attrs);
	}

	public File getFile() {
		return file;
	}

	public String getDirectory() {
		return file != null ? file.getParent() : tempFile.getParent();
	}
	
	public SarifDataFrame getDataFrame() {
		return df;
	}

	public SarifProgramOptions getOptions() {
		return options;
	}

	public String getFileContents() {
		return fileContents;
	}

	public void setFileContents(String fileContents) {
		this.fileContents = fileContents;
	}

	public Writer getBaseWriter() {
		return baseWriter;
	}
	
	// FOR TESTING
	public void useTempFileForBytes(String tempDir) throws IOException {
		File dir = new File(tempDir);
		String fileName = "SARIF_TEST";
		String suffixName = ".sarif.bytes";
		String filename = fileName + '.';
		tempFile = File.createTempFile(filename, suffixName, dir);
		tempFile.deleteOnExit();	
	}


}
