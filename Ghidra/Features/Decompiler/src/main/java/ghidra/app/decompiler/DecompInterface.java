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
/*
 * Created on Oct 29, 2003
 *
 * Deals with the direct interface between C/C++ decompiler
 */

package ghidra.app.decompiler;

import java.io.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * This is a self-contained interface to a single decompile
 * process, suitable for an open-ended number of function
 * decompilations for a single program. The interface is
 * persistent. It caches all the initialization data passed
 * to it, and if the underlying decompiler process crashes,
 * it automatically respawns the process and reinitializes
 * it the next time it is needed.  The basic usage pattern
 * is as follows<pre>
 * 
 *   // Instantiate the interface
 *   DecompInterface ifc = new DecompInterface();
 *   
 *   // Setup any options or other initialization
 *   ifc.setOptions(options); // Inform interface of global options
 *   // ifc.toggleSyntaxTree(false);  // Don't produce syntax trees
 *   // ifc.toggleCCode(false);       // Don't produce C code
 *   // ifc.setSimplificationStyle("normalize"); // Alternate analysis style
 *   
 *   // Setup up the actual decompiler process for a
 *   // particular program, using all the above initialization
 *   ifc.openProgram(program,language);
 *   
 *   // Make calls to the decompiler:
 *   DecompileResults res = ifc.decompileFunction(func,0,taskmonitor);
 *   
 *   // Check for error conditions
 *   if (!res.decompileCompleted()) {
 *   	system.out.println(res.getErrorMessage());
 *      return;
 *   }
 *   
 *   // Make use of results
 *      // Get C code
 *   ClangTokenGroup tokgroup = res.getCCodeMarkup();
 *   ...  
 *      // Get the function object/syntax tree
 *   HighFunction hfunc = res.getHighFunction();
 *   ...
 *   
 * </pre>
 */
public class DecompInterface {

	public static class EncodeDecodeSet {
		public OverlayAddressSpace overlay;		// Active overlay space or null
		public Encoder mainQuery;		// Encoder for main query to decompiler process
		public PackedDecode mainResponse;	// Decoder for main response from the decompiler process
		public PackedDecode callbackQuery;	// Decoder for queries from the decompiler process
		public PackedEncode callbackResponse;	// Encode for response to decompiler queries

		/**
		 * Set up encoders and decoders for functions that are not in overlay address spaces
		 * @param program is the active Program
		 */
		public EncodeDecodeSet(Program program) {
			overlay = null;
			mainQuery = new PackedEncode();
			mainResponse = new PackedDecode(program.getAddressFactory());
			callbackQuery = new PackedDecode(program.getAddressFactory());
			callbackResponse = new PackedEncode();
		}

		/**
		 * Set up encoders and decoders for functions in an overlay space
		 * @param program is the active Program
		 * @param spc is the initial overlay space to set up for
		 * @throws AddressFormatException if address translation is not supported for the overlay
		 */
		public EncodeDecodeSet(Program program, OverlayAddressSpace spc)
				throws AddressFormatException {
			mainQuery = new PackedEncodeOverlay(spc);
			mainResponse = new PackedDecodeOverlay(program.getAddressFactory(), spc);
			callbackQuery = new PackedDecodeOverlay(program.getAddressFactory(), spc);
			callbackResponse = new PackedEncodeOverlay(spc);
		}

		public void setOverlay(OverlayAddressSpace spc) throws AddressFormatException {
			if (overlay == spc) {
				return;
			}
			overlay = spc;
			((PackedEncodeOverlay) mainQuery).setOverlay(spc);
			((PackedDecodeOverlay) mainResponse).setOverlay(spc);
			((PackedDecodeOverlay) callbackQuery).setOverlay(spc);
			((PackedEncodeOverlay) callbackResponse).setOverlay(spc);
		}
	}

	protected Program program;
	private SleighLanguage pcodelanguage;
	private PcodeDataTypeManager dtmanage;
	// Last warning messages from the decompiler
	// or other error message
	protected String decompileMessage;
	protected CompilerSpec compilerSpec;
	protected DecompileProcess decompProcess;
	protected DecompileCallback decompCallback;
	protected EncodeDecodeSet baseEncodingSet;		// Encoders/decoders for functions not in overlay
	protected EncodeDecodeSet overlayEncodingSet;	// Encoders/decoders for functions in overlays
	protected StringIngest stringResponse = new StringIngest();	// Ingester for simple responses
	private DecompileDebug debug;
	protected CancelledListener monitorListener = new CancelledListener() {
		@Override
		public void cancelled() {
			stopProcess();
		}
	};

	// Initialization state
	private String actionname; // Name of simplification action
	private DecompileOptions options; // Current decompiler options
	private boolean printSyntaxTree; // Whether syntax tree is returned
	private boolean printCCode; // Whether C code is returned
	private boolean sendParamMeasures; // Whether Parameter Measures are returned
	private boolean jumpLoad; // Whether jumptable load information is returned

	public DecompInterface() {
		program = null;
		pcodelanguage = null;
		dtmanage = null;
		decompCallback = null;
		options = null;
		baseEncodingSet = null;
		overlayEncodingSet = null;
		debug = null;
		decompileMessage = "";
		compilerSpec = null;
		actionname = "decompile";
		printSyntaxTree = true;
		printCCode = true;
		sendParamMeasures = false;
		jumpLoad = false;
	}

	/**
	 * Turn on debugging dump for the next decompiled
	 * function
	 * @param debugfile the file to enable debug dubp
	 */
	public synchronized void enableDebug(File debugfile) {
		debug = new DecompileDebug(debugfile);
	}

	/**
	 * @return true if debug has been enabled for the current/next decompilation.
	 */
	public boolean debugEnabled() {
		return debug != null;
	}

	/**
	 * Return the identifier for the current simplification style
	 * @return the identifier as a String
	 */
	public String getSimplificationStyle() {
		return actionname;
	}

	public Program getProgram() {
		return program;
	}

	public Language getLanguage() {
		return pcodelanguage;
	}

	public PcodeDataTypeManager getDataTypeManager() {
		return dtmanage;
	}

	/**
	 * Get the last message produced by the decompiler process.
	 * If the message is non-null, it is probably an error
	 * message, but not always.  It is better to use the
	 * getErrorMessage method off of DecompileResults.
	 * @return the message string or null
	 */
	public String getLastMessage() {
		return decompileMessage;
	}

	private boolean isErrorMessage() {
		if (decompileMessage == null || decompileMessage.length() == 0) {
			return false;
		}

		// do not count warning messages as error messages
		if (decompileMessage.toLowerCase().indexOf("warning") != -1) {
			return false;
		}

		return true;
	}

	private static String fileToString(ResourceFile file) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
		try {
			StringBuffer buffer = new StringBuffer();
			String line = null;
			while ((line = reader.readLine()) != null) {
				buffer.append(line);
			}
			return buffer.toString();
		}
		finally {
			reader.close();
		}
	}

	/**
	 * This is the main routine for making sure that a decompiler
	 * process is active and that it is initialized properly
	 * @throws IOException for any problems with the pipe to the decompiler process
	 * @throws DecompileException for errors initializing decompiler options etc.
	 */
	protected void initializeProcess() throws IOException, DecompileException {
		if (decompCallback == null) {
			throw new IOException("Program not opened in decompiler");
		}
		if (decompProcess == null) {
			decompProcess = DecompileProcessFactory.get();
		}
		else if (!decompProcess.isReady()) {
			DecompileProcessFactory.release(decompProcess);
			decompProcess = DecompileProcessFactory.get();
		}
		long uniqueBase = UniqueLayout.SLEIGH_BASE.getOffset(pcodelanguage);
		XmlEncode xmlEncode = new XmlEncode();
		pcodelanguage.encodeTranslator(xmlEncode, program.getAddressFactory(), uniqueBase);
		String tspec = xmlEncode.toString();
		xmlEncode.clear();
		dtmanage.encodeCoreTypes(xmlEncode);
		String coretypes = xmlEncode.toString();
		SleighLanguageDescription sleighdescription =
			(SleighLanguageDescription) pcodelanguage.getLanguageDescription();
		ResourceFile pspecfile = sleighdescription.getSpecFile();
		String pspecxml = fileToString(pspecfile);
		xmlEncode.clear();
		compilerSpec.encode(xmlEncode);
		String cspecxml = xmlEncode.toString();
		baseEncodingSet = new EncodeDecodeSet(program);

		decompCallback.setNativeMessage(null);
		decompProcess.registerProgram(decompCallback, pspecxml, cspecxml, tspec, coretypes,
			program);
		String nativeMessage = decompCallback.getNativeMessage();
		if ((nativeMessage != null) && (nativeMessage.length() != 0)) {
			throw new IOException("Could not register program: " + nativeMessage);
		}
		if (options != null) {
			baseEncodingSet.mainQuery.clear();
			options.encode(baseEncodingSet.mainQuery, this);
			decompProcess.setMaxResultSize(options.getMaxPayloadMBytes());
			decompProcess.sendCommand1Param("setOptions", baseEncodingSet.mainQuery,
				stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Did not accept decompiler options");
			}
		}
		if (actionname == null) {
			throw new IOException("Decompile action not specified");
		}
		if (!actionname.equals("decompile")) {
			decompProcess.sendCommand2Params("setAction", actionname, "", stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Could not set decompile action");
			}
		}
		if (!printSyntaxTree) {
			decompProcess.sendCommand2Params("setAction", "", "notree", stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Could not turn off syntax tree");
			}
		}
		if (!printCCode) {
			decompProcess.sendCommand2Params("setAction", "", "noc", stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Could not turn off C printing");
			}
		}
		if (sendParamMeasures) {
			decompProcess.sendCommand2Params("setAction", "", "parammeasures", stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Could not turn on sending of parameter measures");
			}
		}
		if (jumpLoad) {
			decompProcess.sendCommand2Params("setAction", "", "jumpload", stringResponse);
			if (!stringResponse.toString().equals("t")) {
				throw new IOException("Could not turn on jumptable loads");
			}
		}
	}

	protected void verifyProcess() throws IOException, DecompileException {
		if ((decompProcess == null) || (!decompProcess.isReady())) {
			initializeProcess();
		}
		if (!decompProcess.isReady()) {
			throw new IOException("Unable to restart decompiler process");
		}
	}

	/**
	 * This call initializes a new decompiler process to do
	 * decompilations for a new program. This method only
	 * needs to be called once per program.  Even if the
	 * underlying decompiler process crashes, the interface
	 * will automatically restart and reinitialize a new
	 * process when it needs it, and the openProgram call
	 * does not need to be made again. The call can be made
	 * multiple times, in which case, each call terminates
	 * the process initialized the last time and starts a
	 * new process
	 * @param prog = the program on which to perform decompilations
	 * @return true if the decompiler process is successfully initialized
	 */
	public synchronized boolean openProgram(Program prog) {
		decompileMessage = "";
		program = prog;
		Language lang = prog.getLanguage();
		if (!lang.supportsPcode()) {
			decompileMessage = "Language does not support PCode.";
			return false;
		}
		pcodelanguage = (SleighLanguage) lang;
		CompilerSpec spec = prog.getCompilerSpec();
		if (!(spec instanceof BasicCompilerSpec)) {
			decompileMessage =
				"Language has unsupported compiler spec: " + spec.getClass().getName();
			return false;
		}
		compilerSpec = spec;

		dtmanage = new PcodeDataTypeManager(prog);
		try {
			decompCallback =
				new DecompileCallback(prog, pcodelanguage, program.getCompilerSpec(), dtmanage);
			initializeProcess();
			if (!decompProcess.isReady()) {
				throw new IOException("Unable to start decompiler process");
			}
			decompileMessage = decompCallback.getNativeMessage();
			if (!isErrorMessage()) {
				return true;
			}
		}
		catch (Exception ex) {
			decompileMessage = ex.getMessage();
			if (decompProcess == null) {
				return false;
			}
			stopProcess();
		}
		program = null;
		decompCallback = null;
		baseEncodingSet = null;

		return false;
	}

	/**
	 * Shutdown any existing decompiler process and free
	 * resources.  The interface cannot be used again
	 * to perform decompilations until an openProgram call
	 * is made again.
	 */
	public synchronized void closeProgram() {
		decompileMessage = "";
		if (program != null) {
			program = null;
			decompCallback = null;
			baseEncodingSet = null;
			overlayEncodingSet = null;
			try {
				if ((decompProcess != null) && decompProcess.isReady()) {
					decompProcess.deregisterProgram();
					DecompileProcessFactory.release(decompProcess);
				}
			}
			catch (IOException e) {
				// don't care
			}
			catch (DecompileException e) {
				// don't care
			}
			stopProcess();
		}
	}

	/**
	 * This allows the application to the type of analysis
	 * performed by the decompiler, by giving the name of
	 * an analysis class. Right now, there are a few
	 * predefined classes. But there soon may be support
	 * for applications to define their own class and
	 * tailoring the decompiler's behaviour for that class.
	 * <p>
	 * The current predefined analysis class are:
	 * <ul>
	 *   <li>"decompile" - this is the default, and performs all
	 *      analysis steps suitable for producing C code.
	 *   <li>"normalize" - omits type recovery from the analysis
	 *      and some of the final clean-up steps involved in
	 *      making valid C code.  It is suitable for creating
	 *      normalized pcode syntax trees of the dataflow.
	 *   <li>"firstpass" - does no analysis, but produces an
	 *      unmodified syntax tree of the dataflow from the
	 *   <li>"register" - does ???.
	 *   <li>"paramid" - does required amount of decompilation
	 *      followed by analysis steps that send parameter
	 *      measure information for parameter id analysis.
	 *      raw pcode.
	 * </ul>
	 *      
	 * <p>
	 * This property should ideally be set once before the
	 * openProgram call is made, but it can be used repeatedly
	 * if the application needs to change analysis style in the
	 * middle of a sequence of decompiles.  Unless the style
	 * changes, the method does NOT need to be called repeatedly.
	 * Even after a crash, the new decompiler process will
	 * automatically configured with the cached style value.
	 * 
	 * @param actionstring "decompile"|"normalize"|"register"|"firstpass"|"paramid"
	 * @return true - if the decompiler process was successfully configured
	 */
	public synchronized boolean setSimplificationStyle(String actionstring) {
		actionname = actionstring;
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		try {
			verifyProcess();
			decompProcess.sendCommand2Params("setAction", actionstring, "", stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * This method toggles whether or not the decompiler
	 * produces a syntax tree (via calls to decompileFunction).
	 * The default is to always produce a syntax tree, but
	 * some applications may only need C code.  Ideally this method should
	 * be called once before the openProgram call, but it
	 * can be used at any time, if the application wants
	 * to change before in the middle of a sequence of
	 * decompiles. Unless the desired value changes, the
	 * method does NOT need to be called repeatedly. Even
	 * after a decompiler process crash, the old value is
	 * cached and automatically sent to the new process
	 * @param val = true, to produce a syntax tree, false otherwise
	 * @return true if the decompiler process, accepted the change of state
	 */
	public synchronized boolean toggleSyntaxTree(boolean val) {
		printSyntaxTree = val;
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		String printstring = val ? "tree" : "notree";
		try {
			verifyProcess();
			decompProcess.sendCommand2Params("setAction", "", printstring, stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * Toggle whether or not calls to the decompiler process
	 * (via the decompileFunction method) produce C code.
	 * The default is to always compute C code, but some
	 * applications may only need the syntax tree or other
	 * function information. Ideally this method should
	 * be called once before the openProgram call, but it
	 * can be used at any time, if the application wants
	 * to change before in the middle of a sequence of
	 * decompiles. Unless the desired value changes, the
	 * method does NOT need to be called repeatedly. Even
	 * after a decompiler process crash, the old value is
	 * cached and automatically sent to the new process
	 * @param val = true, to produce C code, false otherwise
	 * @return true if the decompiler process accepted the new state
	 */
	public synchronized boolean toggleCCode(boolean val) {
		printCCode = val;
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		String printstring = val ? "c" : "noc";
		try {
			verifyProcess();
			decompProcess.sendCommand2Params("setAction", "", printstring, stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * Toggle whether or not calls to the decompiler process
	 * (via the decompileFunction method) produce Parameter
	 * Measures. The default is to not compute Parameter
	 * Measures. Ideally this method should
	 * be called once before the openProgram call, but it
	 * can be used at any time, if the application wants
	 * to change before in the middle of a sequence of
	 * decompiles. Unless the desired value changes, the
	 * method does NOT need to be called repeatedly. Even
	 * after a decompiler process crash, the old value is
	 * cached and automatically sent to the new process
	 * @param val = true, to produce C code, false otherwise
	 * @return true if the decompiler process accepted the new state
	 */
	public synchronized boolean toggleParamMeasures(boolean val) {
		sendParamMeasures = val;
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		String printstring = val ? "parammeasures" : "noparammeasures";
		try {
			verifyProcess();
			decompProcess.sendCommand2Params("setAction", "", printstring, stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * Toggle whether or not the decompiler process should return information about tables
	 * used to recover switch statements.  Most compilers implement switch statements using a
	 * so called "jumptable" of addresses or offsets.  The decompiler can frequently recover this
	 * and can return a description of the table
	 * @param val = true, to have the decompiler return table info, false otherwise
	 * @return true if the decompiler process accepted the new state
	 */
	public synchronized boolean toggleJumpLoads(boolean val) {
		jumpLoad = val;
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		String jumpstring = val ? "jumpload" : "nojumpload";
		try {
			verifyProcess();
			decompProcess.sendCommand2Params("setAction", "", jumpstring, stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * Set the object controlling the list of global options
	 * used by the decompiler. Ideally this is called once,
	 * before the openProgram call is made. But it can be
	 * used at any time, if the options change in the middle
	 * of a sequence of decompiles.
	 * If there is no change to the options, this method
	 * does NOT need to be called repeatedly.  Even after
	 * recovering from decompiler process crash, the interface
	 * keeps the options object around and automatically
	 * sends it to the new decompiler process.
	 * @param options the new (or changed) option object
	 * @return true if the decompiler process accepted the new options
	 */
	public synchronized boolean setOptions(DecompileOptions options) {
		this.options = options;
		decompileMessage = "";
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		try {
			verifyProcess();
			baseEncodingSet.mainQuery.clear();
			options.encode(baseEncodingSet.mainQuery, this);
			decompProcess.setMaxResultSize(options.getMaxPayloadMBytes());
			decompProcess.sendCommand1Param("setOptions", baseEncodingSet.mainQuery,
				stringResponse);
			return stringResponse.toString().equals("t");
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return false;
	}

	/**
	 * Get the options currently in effect for the decompiler
	 * 
	 * @return options that will be passed to the decompiler
	 */
	public synchronized DecompileOptions getOptions() {
		return this.options;
	}

	/**
	 * Tell the decompiler to clear any function and symbol
	 * information it gathered from the database.  Its a good
	 * idea to call this after any decompileFunction call,
	 * as the decompile process caches and reuses this kind
	 * of data, and there is no explicit method for keeping
	 * the cache in sync with the data base. Currently the
	 * return value has no meaning.
	 * @return -1
	 */
	public synchronized int flushCache() {
		int res = -1;
		try {
			if ((decompProcess != null) && decompProcess.isReady()) {
				decompProcess.sendCommand("flushNative", stringResponse);
				return Integer.parseInt(stringResponse.toString());
			}
		}
		catch (IOException e) {
			// don't care
		}
		catch (DecompileException e) {
			// don't care
		}
		stopProcess();
		return res;
	}

	public synchronized BlockGraph structureGraph(BlockGraph ingraph, int timeoutSecs,
			TaskMonitor monitor) {
		decompileMessage = "";
		if (monitor != null && monitor.isCancelled()) {
			return null;
		}
		if (monitor != null) {
			monitor.addCancelledListener(monitorListener);
		}
		BlockGraph resgraph = null;
		try {
			setupEncodeDecode(Address.NO_ADDRESS);
			verifyProcess();
			baseEncodingSet.mainQuery.clear();
			ingraph.encode(baseEncodingSet.mainQuery);
			decompProcess.sendCommandTimeout("structureGraph", timeoutSecs, baseEncodingSet);
			decompileMessage = decompCallback.getNativeMessage();
			if (!baseEncodingSet.mainResponse.isEmpty()) {
				resgraph = new BlockGraph();
				resgraph.decode(baseEncodingSet.mainResponse);
				resgraph.transferObjectRef(ingraph);
			}
		}
		catch (Exception ex) {
			decompileMessage = "Exception while graph structuring: " + ex.getMessage() + '\n';
		}
		finally {
			if (monitor != null) {
				monitor.removeCancelledListener(monitorListener);
			}
		}
		return resgraph;
	}

	/**
	 * Decompile function
	 * @param func function to be decompiled
	 * @param timeoutSecs if decompile does not complete in this time a null value
	 * will be returned and a timeout error set.
	 * @param monitor optional task monitor which may be used to cancel decompile
	 * @return decompiled function text
	 */
	public synchronized DecompileResults decompileFunction(Function func, int timeoutSecs,
			TaskMonitor monitor) {

		decompileMessage = "";
		if (monitor != null && monitor.isCancelled()) {
			return null;
		}

		if (monitor != null) {
			monitor.addCancelledListener(monitorListener);
		}

		if (program == null) {
			return new DecompileResults(func, pcodelanguage, null, dtmanage, decompileMessage, null,
				DecompileProcess.DisposeState.DISPOSED_ON_CANCEL);
		}

		Decoder decoder = null;
		try {
			Address funcEntry = func.getEntryPoint();
			if (debug != null) {
				debug.setFunction(func);
			}
			decompCallback.setFunction(func, funcEntry, debug);
			EncodeDecodeSet activeSet = setupEncodeDecode(funcEntry);
			decoder = activeSet.mainResponse;
			verifyProcess();
			activeSet.mainQuery.clear();
			AddressXML.encode(activeSet.mainQuery, funcEntry);
			decompProcess.sendCommandTimeout("decompileAt", timeoutSecs, activeSet);
			decompileMessage = decompCallback.getNativeMessage();
		}
		catch (Exception ex) {
			decoder.clear(); 	// Clear any partial result
			decompileMessage = "Exception while decompiling " + func.getEntryPoint() + ": " +
				ex.getMessage() + '\n';
		}
		finally {
			if (monitor != null) {
				monitor.removeCancelledListener(monitorListener);
			}
		}

		try {
			if (debug != null) {
				XmlEncode xmlEncode = new XmlEncode();
				options.encode(xmlEncode, this);
				debug.shutdown(pcodelanguage, xmlEncode.toString());
				debug = null;
			}
		}
		catch (IOException e) {
			Msg.error(debug, "Could not dump debug info");
		}
		DecompileProcess.DisposeState processState;
		if (decompProcess != null) {
			processState = decompProcess.getDisposeState();
			if (decompProcess.getDisposeState() == DecompileProcess.DisposeState.NOT_DISPOSED) {
				flushCache();
			}
		}
		else {
			processState = DecompileProcess.DisposeState.DISPOSED_ON_CANCEL;
		}

		return new DecompileResults(func, pcodelanguage, compilerSpec, dtmanage, decompileMessage,
			decoder, processState);
	}

	/**
	 * Stop the decompile process. 
	 * 
	 * NOTE: Subsequent calls made from another  
	 * thread to this DecompInterface object may fail since the decompiler 
	 * process is being yanked away.
	 */
	public void stopProcess() {
		if (decompProcess != null) {
			decompProcess.dispose();
		}
	}

	/**
	 * Resets the native decompiler process.  Call this method when the decompiler's view
	 * of a program has been invalidated, such as when a new overlay space has been added.
	 */
	public void resetDecompiler() {
		stopProcess();
		try {
			initializeProcess();
		}
		catch (IOException | DecompileException e) {
			decompileMessage = "Exception while resetting decompiler: " + e.getMessage() + "\n";
		}
	}

	public void dispose() {
		if (program == null) {
			if (decompProcess != null) {
				DecompileProcessFactory.release(decompProcess);
			}
			return;
		}

		DecompilerDisposer.dispose(this);
	}

	/** Our threaded callback */
	void disposeCallback() {
		closeProgram();
	}

	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	/**
	 * Setup the correct Encoder and Decoder to use for the decompilation.
	 * Generally we use the base versions unless there is an overlay. In which case we switch
	 * to special translating encoders and decoders.
	 * @param addr is the address of the function being decompiled
	 * @return the set of encoders and decoders that should be used
	 * @throws AddressFormatException if decompilation is not supported for the (overlay) address
	 */
	protected EncodeDecodeSet setupEncodeDecode(Address addr) throws AddressFormatException {
		AddressSpace spc = addr.getAddressSpace();
		if (!spc.isOverlaySpace()) {
			return baseEncodingSet;
		}
		OverlayAddressSpace overlay = (OverlayAddressSpace) spc;
		if (overlayEncodingSet == null) {
			overlayEncodingSet = new EncodeDecodeSet(program, overlay);
		}
		else {
			overlayEncodingSet.setOverlay(overlay);
		}
		return overlayEncodingSet;

	}
}
