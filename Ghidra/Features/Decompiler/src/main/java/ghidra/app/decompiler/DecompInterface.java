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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParser;

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
 *   ifc.setOptions(xmlOptions); // Inform interface of global options
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

	protected Program program;
	private SleighLanguage pcodelanguage;
	private PcodeDataTypeManager dtmanage;
	// Last warning messages from the decompiler
	// or other error message
	protected String decompileMessage;
	protected BasicCompilerSpec compilerSpec;
	protected DecompileProcess decompProcess;
	protected DecompileCallback decompCallback;
	private DecompileDebug debug;
	protected CancelledListener monitorListener = new CancelledListener() {
		@Override
		public void cancelled() {
			stopProcess();
		}
	};

	// Initialization state
	private String actionname; // Name of simplification action
	private DecompileOptions xmlOptions; // Current decompiler options
	private boolean printSyntaxTree; // Whether syntax tree is returned
	private boolean printCCode; // Whether C code is returned
	private boolean sendParamMeasures; // Whether Parameter Measures are returned
	private boolean jumpLoad; // Whether jumptable load information is returned

	public DecompInterface() {
		program = null;
		pcodelanguage = null;
		dtmanage = null;
		decompCallback = null;
		xmlOptions = null;
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
		// use static uniqueBase since we don't know how many dynamically generated 
		// variables Ghidra may add to the language/compile-spec uniqueBase
		long uniqueBase = 0x10000000;
		String tspec =
			pcodelanguage.buildTranslatorTag(program.getAddressFactory(), uniqueBase, null);
		String coretypes = dtmanage.buildCoreTypes();
		SleighLanguageDescription sleighdescription =
			(SleighLanguageDescription) pcodelanguage.getLanguageDescription();
		ResourceFile pspecfile = sleighdescription.getSpecFile();
		String pspecxml = fileToString(pspecfile);
		String cspecxml = compilerSpec.getXMLString();

		decompCallback.setNativeMessage(null);
		decompProcess.registerProgram(decompCallback, pspecxml, cspecxml, tspec, coretypes);
		String nativeMessage = decompCallback.getNativeMessage();
		if ((nativeMessage != null) && (nativeMessage.length() != 0)) {
			throw new IOException("Could not register program: " + nativeMessage);
		}
		if (xmlOptions != null) {
			decompProcess.setMaxResultSize(xmlOptions.getMaxPayloadMBytes());
			if (!decompProcess.sendCommand1Param("setOptions", xmlOptions.getXML(this))
					.toString()
					.equals("t")) {
				throw new IOException("Did not accept decompiler options");
			}
		}
		if (actionname == null) {
			throw new IOException("Decompile action not specified");
		}
		if (!actionname.equals("decompile")) {
			if (!decompProcess.sendCommand2Params("setAction", actionname, "")
					.toString()
					.equals("t")) {
				throw new IOException("Could not set decompile action");
			}
		}
		if (!printSyntaxTree) {
			if (!decompProcess.sendCommand2Params("setAction", "", "notree")
					.toString()
					.equals("t")) {
				throw new IOException("Could not turn off syntax tree");
			}
		}
		if (!printCCode) {
			if (!decompProcess.sendCommand2Params("setAction", "", "noc").toString().equals("t")) {
				throw new IOException("Could not turn off C printing");
			}
		}
		if (sendParamMeasures) {
			if (!decompProcess.sendCommand2Params("setAction", "", "parammeasures")
					.toString()
					.equals("t")) {
				throw new IOException("Could not turn on sending of parameter measures");
			}
		}
		if (jumpLoad) {
			if (!decompProcess.sendCommand2Params("setAction", "", "jumpload")
					.toString()
					.equals("t")) {
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
		compilerSpec = (BasicCompilerSpec) spec;

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
			return decompProcess.sendCommand2Params("setAction", actionstring, "")
					.toString()
					.equals("t");
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
			return decompProcess.sendCommand2Params("setAction", "", printstring)
					.toString()
					.equals("t");
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
			return decompProcess.sendCommand2Params("setAction", "", printstring)
					.toString()
					.equals("t");
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
			return decompProcess.sendCommand2Params("setAction", "", printstring)
					.toString()
					.equals("t");
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
			return decompProcess.sendCommand2Params("setAction", "", jumpstring)
					.toString()
					.equals("t");
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
	 * @param xmloptions the new (or changed) option object
	 * @return true if the decompiler process accepted the new options
	 */
	public synchronized boolean setOptions(DecompileOptions xmloptions) {
		this.xmlOptions = xmloptions;
		decompileMessage = "";
		// Property can be set before process exists
		if (decompProcess == null) {
			return true;
		}
		try {
			verifyProcess();
			decompProcess.setMaxResultSize(xmlOptions.getMaxPayloadMBytes());
			return decompProcess.sendCommand1Param("setOptions", xmloptions.getXML(this))
					.toString()
					.equals("t");
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
		return this.xmlOptions;
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
				String retval = decompProcess.sendCommand("flushNative").toString();
				return Integer.parseInt(retval);
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

	public synchronized BlockGraph structureGraph(BlockGraph ingraph, AddressFactory factory,
			int timeoutSecs, TaskMonitor monitor) {
		decompileMessage = "";
		if (monitor != null && monitor.isCancelled()) {
			return null;
		}
		if (monitor != null) {
			monitor.addCancelledListener(monitorListener);
		}
		LimitedByteBuffer res = null;
		BlockGraph resgraph = null;
		try {
			StringWriter writer = new StringWriter();
			ingraph.saveXml(writer);
			verifyProcess();
			res = decompProcess.sendCommand1ParamTimeout("structureGraph", writer.toString(),
				timeoutSecs);
			decompileMessage = decompCallback.getNativeMessage();
			if (res != null) {
				XmlPullParser parser = HighFunction.stringTree(res.getInputStream(),
					HighFunction.getErrorHandler(this, "Results for structureGraph command"));
				resgraph = new BlockGraph();
				resgraph.restoreXml(parser, factory);
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

		LimitedByteBuffer res = null;
		if (monitor != null) {
			monitor.addCancelledListener(monitorListener);
		}

		if (program == null) {
			return new DecompileResults(func, pcodelanguage, null, dtmanage, decompileMessage, null,
				DecompileProcess.DisposeState.DISPOSED_ON_CANCEL);
		}

		try {
			Address funcEntry = func.getEntryPoint();
			if (debug != null) {
				debug.setFunction(func);
			}
			decompCallback.setFunction(func, funcEntry, debug);
			StringBuilder addrBuf = new StringBuilder();
			AddressXML.buildXML(addrBuf, funcEntry);
			verifyProcess();
			res = decompProcess.sendCommand1ParamTimeout("decompileAt", addrBuf.toString(),
				timeoutSecs);
			decompileMessage = decompCallback.getNativeMessage();
		}
		catch (Exception ex) {
			decompileMessage = "Exception while decompiling " + func.getEntryPoint() + ": " +
				ex.getMessage() + '\n';
		}
		finally {
			if (monitor != null) {
				monitor.removeCancelledListener(monitorListener);
			}
		}
		if (debug != null) {
			debug.shutdown(pcodelanguage, xmlOptions.getXML(this));
			debug = null;
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

		InputStream stream = null;
		if (res != null) {
			stream = res.getInputStream();
		}
		return new DecompileResults(func, pcodelanguage, compilerSpec, dtmanage, decompileMessage,
			stream, processState);
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
}
