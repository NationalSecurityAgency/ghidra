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
package ghidra.features.bsim.query;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiPredicate;

import generic.jar.ResourceFile;
import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType;
import ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.PreFilter;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Generate decompiler signatures for a set of functions
 *
 */
public class GenSignatures {
	private DescriptionManager manager;
	private LSHVectorFactory vectorFactory;
	private Program program;				// Current program being analyzed
	private FunctionManager fmanage;
	private DecompileOptions options;
	private ExecutableRecord exerec;
	private SignatureTask singletask;		// Task for processing one function at a time
	private HashMap<String, Integer> attributes;		// Attributes to associate with functions
	private List<String> categories;	// Category types associated with executables
	private String dateColumnName;
	private boolean gencallgraph;			// True if callgraph info should be generated along with signatures

	private AtomicBoolean isShutdown = new AtomicBoolean(false);
	private ConcurrentLinkedDeque<ParallelDecompileTask> runningTasks =
		new ConcurrentLinkedDeque<>();

	/**
	 * Prepare for generation of signature information and (possibly) callgraph information
	 * @param callgraph is true if the user wants callgraph information to be generated at the same time as signatures
	 */
	public GenSignatures(boolean callgraph) {
		vectorFactory = null;
		options = null;
		exerec = null;
		singletask = null;
		gencallgraph = callgraph;

		attributes = new HashMap<String, Integer>();
		attributes.put("Function ID Analyzer", FunctionTagBSimFilterType.KNOWN_LIBRARY_MASK);
		categories = null;
		dateColumnName = null;
	}

	public void addExecutableCategories(List<String> names) {
		if (names == null) {
			return;
		}
		for (String name : names) {
			if (!CategoryRecord.enforceTypeCharacters(name)) {
				throw new IllegalArgumentException();
			}
			if (categories == null) {
				categories = new ArrayList<String>();
			}
			categories.add(name);
		}
	}

	public void addFunctionTags(List<String> names) {
		if (names == null) {
			return;
		}
		int flag = 1;
		flag <<= FunctionTagBSimFilterType.RESERVED_BITS;			// The first bits are reserved
		for (String name : names) {
			if ((flag == 0) || (!CategoryRecord.enforceTypeCharacters(name))) {
				throw new IllegalArgumentException();
			}
			attributes.put(name, flag);
			flag <<= 1;
		}
	}

	public void setVectorFactory(LSHVectorFactory vFactory) throws LSHException {
		if (vFactory.getSettings() == 0) {
			throw new LSHException("Cannot have signature setting of 0");
		}
		if (vectorFactory == vFactory) {	// No change to factory
			return;
		}
		if (manager != null) {
			manager.clearFunctions();	// Clear out cached signature as settings have changed
		}
		vectorFactory = vFactory;
	}

	public void addDateColumnName(String name) {
		if (name == null) {
			return;
		}
		if (!CategoryRecord.enforceTypeCharacters(name)) {
			throw new IllegalArgumentException();
		}
		dateColumnName = name;
	}

	public DescriptionManager getDescriptionManager() {
		return manager;
	}

	/**
	 * Clear out any accumulated signatures
	 */
	public void clear() {
		if (manager != null) {
			manager.clear();
		}
		manager = null;
		program = null;		// Cannot reuse unless we call openProgram again
	}

	/**
	 * Generate an MD5 hash based just on executable metadata
	 * @param nmover is name of executable
	 * @param compover is architecture metadata
	 * @param archover is architecture metadata
	 * @return the md5 result as an ascii string
	 */
	private String generateMetadataMD5(String nmover, String compover, String archover) {
		//  until we can get full hash
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte data[] = new byte[nmover.length() + compover.length() + archover.length()];
		int pos = 0;
		for (int i = 0; i < nmover.length(); ++i) {
			data[pos++] = (byte) nmover.charAt(i);
		}
		for (int i = 0; i < compover.length(); ++i) {
			data[pos++] = (byte) compover.charAt(i);
		}
		for (int i = 0; i < archover.length(); ++i) {
			data[pos++] = (byte) archover.charAt(i);
		}
		digester.update(data);
		byte[] digest = digester.digest();
		StringBuffer buf = new StringBuffer();
		char[] hexdigits =
			{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		for (int i = 0; i < 16; ++i) {
			char val1 = hexdigits[(digest[i] >> 4) & 0xf];
			char val2 = hexdigits[digest[i] & 0xf];
			buf.append(val1).append(val2);
		}
		return buf.toString();
	}

	/**
	 * Prepare to collect signatures for a new program, essentially by starting up a new decompiler process
	 * and creating an ExecutableRecord
	 * @param prog is the program to prepare for
	 * @param nmover if not null, overrides the "name" of the executable
	 * @param archover if not null, overrides the "architecture" of the executable
	 * @param compover if not null, overrides the "compiler" used to build the executable
	 * @param repo the repository containing the executable
	 * @param path the path (within the repo) where the executable can be found
	 * @throws LSHException if a new executable record cannot be created
	 */
	public void openProgram(Program prog, String nmover, String archover, String compover,
			String repo, String path) throws LSHException {
		program = prog;

		if (nmover == null) {
			nmover = program.getDomainFile().getName();
		}
		if (archover == null) {
			archover = program.getLanguageID().getIdAsString();
		}
		if (compover == null) {
			compover = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
		}

		String md5string = prog.getExecutableMD5();
		if ((md5string == null) || (md5string.length() < 10)) {
			md5string = generateMetadataMD5(nmover, compover, archover);
		}
		Date progDate = fillinDate();
		manager = new DescriptionManager();
		exerec = manager.newExecutableRecord(md5string, nmover, compover, archover, progDate, repo,
			path, null);
		singletask = null;		// Throw out any old decompiler process
		fmanage = program.getFunctionManager();
		fillinExecutableCategories();
	}

	private void fillinExecutableCategories() {
		if (categories == null) {
			return;
		}
		List<CategoryRecord> catrecs = new ArrayList<CategoryRecord>();
		Options progoptions = program.getOptions(Program.PROGRAM_INFO);
		for (String cat : categories) {	// Search for each of the categories we want to record
			String curproperty = cat;
			int count = 0;
			while (progoptions.contains(curproperty)) {
				Object optionobject = progoptions.getObject(curproperty, null);
				if (optionobject instanceof String) {
					CategoryRecord rec = new CategoryRecord(cat, (String) optionobject);
					catrecs.add(rec);
				}
				else {
					break;
				}
				count += 1;
				curproperty = cat + '_' + Integer.toString(count);
			}
		}
		if (!catrecs.isEmpty()) {
			manager.setExeCategories(exerec, catrecs);
		}
	}

	private Date fillinDate() {
		if ((dateColumnName == null) || dateColumnName.equals(Program.DATE_CREATED) ||
			dateColumnName.equals("Ingest Date")) {
			return program.getCreationDate();
		}
		Options progoptions = program.getOptions(Program.PROGRAM_INFO);
		if (!progoptions.contains(dateColumnName)) {
			return ExecutableRecord.EMPTY_DATE;
		}
		Object optionobject = progoptions.getObject(dateColumnName, null);
		if (optionobject instanceof Date) {
			return (Date) optionobject;
		}
		Date res = ExecutableRecord.EMPTY_DATE;
		if (optionobject instanceof String) {
			String str = (String) optionobject;
			if (str.length() == 19) {
				SimpleDateFormat dateFormat =
					new SimpleDateFormat(AbstractSQLFunctionDatabase.JAVA_TIME_FORMAT);
				try {
					res = dateFormat.parse(str);
				}
				catch (ParseException e) {
					res = ExecutableRecord.EMPTY_DATE;
				}
			}
		}
		return res;
	}

	private CallRecord fillinProperties(Address addr) {
		CallRecord callRecord = new CallRecord();
		Function func = fmanage.getReferencedFunction(addr);
		Symbol rootSymbol = null;
		Address rootAddr = null;
		boolean hasbody = false;
		if (func == null) {							// Found no function at all
			SymbolTable symtab = program.getSymbolTable();
			rootSymbol = symtab.getPrimarySymbol(addr);		// Look for any primary symbol
		}
		else {
			if (func.isThunk()) {						// Function looks like a thunk
				func = func.getThunkedFunction(true);
			}
			rootAddr = func.getEntryPoint();
			rootSymbol = func.getSymbol();
			if (!func.isExternal()) {
				hasbody = hasBody(rootAddr);
			}
		}
		if (hasbody) {	// Internal call
			callRecord.exerec = exerec;		// Within the same executable
			callRecord.spaceid = rootAddr.getAddressSpace().getSpaceID();
			callRecord.address = rootAddr.getOffset();
			callRecord.funcname = rootSymbol.getName(true);
		}
		else {	// Treat as external call
			callRecord.address = -1;		// Address not available, indicate an external call
			String libraryName;
			if (rootSymbol == null) {
				libraryName = "unknown";
				callRecord.funcname = "func_" + Long.toHexString(addr.getOffset());	// Make up a name				
			}
			else {
				libraryName = extractExternalName(rootSymbol, callRecord);
			}
			try {
				callRecord.exerec =
					manager.newExecutableLibrary(libraryName, exerec.getArchitecture(), null);
			}
			catch (LSHException e) {
				callRecord.exerec = exerec;		// If we couldn't create a library executable, use original executable
			}
		}
		return callRecord;
	}

	private String extractExternalName(Symbol sym, CallRecord callRecord) {
		String fullName = sym.getName(true);
		int ind = fullName.indexOf("::");
		String libraryName;
		if (ind >= 0) {
			libraryName = fullName.substring(0, ind);			// First namespace is name of library
			String tmpnm = fullName.substring(ind + 2);	// Cut off first namespace
			if (tmpnm.isEmpty()) {
				libraryName = "unknown";
				callRecord.funcname = fullName;
			}
			else if (libraryName.isEmpty()) {
				libraryName = "unknown";
				callRecord.funcname = tmpnm;
			}
			else {
				callRecord.funcname = tmpnm;
			}
			if (libraryName.equals(Library.UNKNOWN)) {
				libraryName = "unknown";
			}
		}
		else {
			libraryName = "unknown";
			callRecord.funcname = fullName;
		}
		return libraryName;
	}

	private int recoverAttributes(Function func) {
		int flags = 0;
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Bookmark[] bookmarks = bookmarkManager.getBookmarks(func.getEntryPoint());
		for (Bookmark bookmark : bookmarks) {
			Integer val = attributes.get(bookmark.getCategory());
			if (val != null) {
				flags |= val.intValue();
			}
		}
		Set<FunctionTag> tags = func.getTags();
		for (FunctionTag tag : tags) {
			Integer val = attributes.get(tag.getName());
			if (val != null) {
				flags |= val.intValue();
			}
		}
		return flags;
	}

	private List<CallRecord> collectCallsFromAddress(List<Address> calladdr) {
		List<CallRecord> calls = new ArrayList<CallRecord>();
		for (int i = 0; i < calladdr.size(); ++i) {
			Address addr = calladdr.get(i);
			CallRecord callRecord = fillinProperties(addr);
			calls.add(callRecord);
		}
		return calls;
	}

	/**
	 * Return true if the address corresponds to a normal function body
	 * @param addr is the entry point of the function
	 * @return true if it has a body
	 */
	private boolean hasBody(Address addr) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr);
		if (!(cu instanceof Instruction)) {		// If the entry point is data -> no body
			return false;
		}

		Instruction inst = (Instruction) cu;
		FlowType flowType = inst.getFlowType();
		if (flowType == RefType.COMPUTED_JUMP) {
			return false;
		}

		return true;
	}

	private synchronized void writeToManager(Function func, int[] hash, List<CallRecord> callrecs,
			int flags) {

        Address entryPoint = func.getEntryPoint();
		FunctionDescription fdesc = manager.newFunctionDescription(func.getName(true),
				entryPoint.getAddressSpace().getSpaceID(), entryPoint.getOffset(), exerec);
        manager.setFunctionDescriptionFlags(fdesc, flags);
		if (hash != null) {
			LSHVector vec = vectorFactory.buildVector(hash);
			SignatureRecord sigrec = manager.newSignature(vec, 0);
			manager.attachSignature(fdesc, sigrec);
		}
		for (CallRecord callRecord : callrecs) {
			FunctionDescription destfunc = manager.newFunctionDescription(callRecord.funcname,
				callRecord.spaceid, callRecord.address, callRecord.exerec);
			manager.makeCallgraphLink(fdesc, destfunc, 0);
		}
	}

	public int transferCachedFunctions(DescriptionManager otherman, Iterator<Function> functions,
			PreFilter preFilter) throws LSHException {
		otherman.transferSettings(manager);
		int count = 0;
		BiPredicate<Program, FunctionDescription> filterPredicate =
			preFilter.getAndReducedPredicate();
		while (functions.hasNext()) {
			FunctionDescription desc;
			Function func = functions.next();
			String name = func.getName(true);
			long address = func.getEntryPoint().getOffset();
			int spaceid = func.getEntryPoint().getAddressSpace().getSpaceID();
			try {
				desc = manager.findFunction(name, spaceid, address, exerec);
			}
			catch (LSHException e) {		// This exception is thrown if the manager does not contain a function of this name
				continue;					// Basically we skip the function in this case
			}
			if (filterPredicate.test(program, desc)) {
				otherman.transferFunction(desc, true);
				count += 1;
			}
		}
		return count;
	}

	/**
	 * Generate signatures for a (potentially large) set of functions by spawning multiple
	 * threads to parallelize the work
	 *
	 * @param functions the set of functions to signature
	 * @param countestimate estimated number of functions (to initialize the monitor)
	 * @param monitor controls interruptions and progress reports
	 * @throws DecompileException if the functions cannot be decompiled
	 */
	public void scanFunctions(Iterator<Function> functions, int countestimate, TaskMonitor monitor)
			throws DecompileException {

		if (!functions.hasNext()) {
			return;
		}

		if (isShutdown.get()) {
			return;
		}

		ParallelDecompileTask taskrun =
			new ParallelDecompileTask(program, monitor, new SignatureTask());
		runningTasks.add(taskrun);
		taskrun.decompile(functions, countestimate);
		runningTasks.remove(taskrun);
	}

	/**
	 * Calculate signatures for a single function
	 * @param func is the function to scan
	 * @throws DecompileException if the decompiler task fails
	 */
	public void scanFunction(Function func) throws DecompileException {
		if (isShutdown.get()) {
			return;
		}

		if (singletask == null) {
			singletask = new SignatureTask();
			singletask.initializeGlobal(program);
			singletask = (SignatureTask) singletask.clone(0);	// Start decompiler process
		}

		singletask.decompile(func, null);
	}

	/**
	 * Generate just the update metadata for functions in the currently open program
	 * if -iter- is null, generate metadata for all functions
	 * @param iter iterates over the set of Functions to generate metadata for
	 * @param monitor the task monitor
	 */
	public void scanFunctionsMetadata(Iterator<Function> iter, TaskMonitor monitor) {
		if (exerec == null) {
			return;		// No current executable
		}
		if (iter == null) {
			iter = fmanage.getFunctions(true);
		}
		while (iter.hasNext()) {
			Function func = iter.next();
			if ((monitor != null) && (monitor.isCancelled())) {
				return;
			}
			if (func.isThunk()) {
				continue;
			}
			if (!hasBody(func.getEntryPoint())) {
				continue;
			}
			int flags = recoverAttributes(func);
			Address entryPoint = func.getEntryPoint();
			FunctionDescription fdesc = manager.newFunctionDescription(func.getName(true),
				entryPoint.getAddressSpace().getSpaceID(), entryPoint.getOffset(), exerec);
			manager.setFunctionDescriptionFlags(fdesc, flags);

		}
	}

	public void dispose() {

		isShutdown.set(true);

		for (ParallelDecompileTask task : runningTasks) {
			task.shutdown();
		}
		runningTasks.clear();

		if (singletask != null) {
			singletask.shutdown();
		}

		clear();
	}

	/**
	 * Build an ExecutableRecord path from the domain file.
	 * WARNING: Make sure the program has been saved previously before calling this, otherwise you get
	 * an (inaccurate) result of "/"
	 * @param program the current program
	 * @return the path to this program within the repository as a string
	 */
	public static String getPathFromDomainFile(Program program) {
		DomainFile domainFile = program.getDomainFile();
		String path = domainFile.getPathname();
		int ind = path.length() - domainFile.getName().length();
		if (ind >= 0) {
			if (!path.substring(ind).equals(domainFile.getName())) {
				ind = -1;
			}
		}
		if (ind <= 0) {
			path = null;
		}
		else {
			path = path.substring(0, ind);
		}
		return path;
	}

	/**
	 * Return the weights file that should be used to compare functions between two programs
	 * @param id1 is the language of the first program
	 * @param id2 is the language of the second program  (can be same as first program)
	 * @return the XML weights file, or null if there is no valid weights file
	 * @throws IOException if the module data directory cannot be found
	 */
	public static ResourceFile getWeightsFile(LanguageID id1, LanguageID id2) throws IOException {
		String[] split1 = id1.getIdAsString().split(":");
		String[] split2 = id2.getIdAsString().split(":");
		// Check if we have are comparing the same processor size
		if ((split1.length < 3) || (split2.length < 3)) {
			return null;		// If not, we need to do something different with the weights
		}

		ResourceFile moduleDataSubDirectory = Application.getModuleDataSubDirectory("");
		if (split1[0].equals("Dalvik") || split1[0].equals("JVM")) {
			if (!split2[0].equals(split1[0])) {
				return null;
			}
			return new ResourceFile(moduleDataSubDirectory, "lshweights_cpool.xml");
		}
		String basefile;
		String size1 = split1[2];		// Pull out the size
		String size2 = split2[2];
		if (!size1.equals(size2)) {		// If the two things we compare are from different processor sizes
			if (!size1.equals("64") && !size1.equals("32")) {
				return null;	// Differing sizes not 32 or 64
			}
			if (!size2.equals("64") && !size2.equals("32")) {
				return null;	// We cannot do decent comparisons
			}
			basefile = "lshweights_nosize.xml";	// We use a special sizeless weights file
		}
		else {
			if (size1.equals("32")) {
				basefile = "lshweights_32.xml";
			}
			else if (size1.equals("64")) {
				basefile = "lshweights_64.xml";
				if (split1.length > 3) {
					String version = split1[3];
					if (version.contains("-32")) {
						basefile = "lshweights_64_32.xml";
					}
				}
			}
			else {
				// Same size, but not 64 or 32
				basefile = "lshweights_nosize.xml";
			}
		}

		return new ResourceFile(moduleDataSubDirectory, basefile);
	}

	/**
	 * Info for resolving a call to a unique function in the database.
	 * For normal functions you need the triple (executable, function name, spaceid, address)
	 * For calls to library (external) functions, only the library executable
	 * and the function name are needed, and the address is filled in with -1
	 */
	private static class CallRecord {
		public ExecutableRecord exerec;
		public String funcname;
		public int spaceid;
		public long address;
	}

	public class SignatureTask implements DecompileFunctionTask {

		private DecompInterface decompiler;

		public SignatureTask() {
			decompiler = null;
		}

		private SignatureTask(DecompInterface decompiler) {
			this.decompiler = decompiler;
		}

		@Override
		public DecompileFunctionTask clone(int worker) throws DecompileException {
			DecompInterface newdecompiler = new DecompInterface();
			newdecompiler.setOptions(options);
			newdecompiler.toggleSyntaxTree(false);
			newdecompiler.setSignatureSettings(vectorFactory.getSettings());
			if (!newdecompiler.openProgram(program)) {
				String errorMessage = newdecompiler.getLastMessage();
				throw new DecompileException("Decompiler",
					"Unable to initialize the DecompilerInterface: " + errorMessage);
			}
			if (worker == 0) {	// Query the first work for settings info
				short major = newdecompiler.getMajorVersion();
				short minor = newdecompiler.getMinorVersion();
				int settings = newdecompiler.getSignatureSettings();
				manager.setVersion(major, minor);
				manager.setSettings(settings);
			}
			return new SignatureTask(newdecompiler);
		}

		@Override
		public void decompile(Function func, TaskMonitor monitor) {
			if ((monitor != null) && (monitor.isCancelled())) {
				return;
			}
			if (func.isThunk()) {
				return;
			}
			Address entryPoint = func.getEntryPoint();
			if (!hasBody(entryPoint)) {
				return;
			}
			FunctionDescription fdesc =
				manager.containsDescription(func.getName(true), entryPoint, exerec);
			if (fdesc != null && fdesc.getSignatureRecord() != null) {	// Is signature for this function already present
				return;
			}
			SignatureResult sigres = decompiler.generateSignatures(func, gencallgraph,
				options.getDefaultTimeout(), monitor);

			if ((monitor != null) && (monitor.isCancelled())) {
				return;
			}

			if (sigres == null) {
				String errmsg = decompiler.getLastMessage();
				if ((errmsg != null) && !errmsg.isEmpty()) {
					//					throw new DecompileException("signature",errmsg);
					Msg.error(this, "Error generating signature for \"" + func.getName() +
						"\".  Error: " + errmsg);
				}
				return;
			}
			else if (sigres.features.length == 0) {
				Msg.error(this, "No features in signature for \"" + func.getName() + '\"');
				return;
			}
			int flags = recoverAttributes(func);
			if (sigres.hasunimplemented) {
				flags |= FunctionTagBSimFilterType.HAS_UNIMPLEMENTED_MASK;
			}
			if (sigres.hasbaddata) {
				flags |= FunctionTagBSimFilterType.HAS_BADDATA_MASK;
			}
			List<CallRecord> callrecs;
			if (gencallgraph) {
				callrecs = collectCallsFromAddress(sigres.calllist);
			}
			else {
				callrecs = new ArrayList<CallRecord>();
			}
			writeToManager(func, sigres.features, callrecs, flags);
		}

		@Override
		public void initializeGlobal(Program prog) {
			program = prog;
			options = new DecompileOptions();
			options.grabFromProgram(program);		// Same options are global across all tasks		
		}

		@Override
		public void shutdown() {
			decompiler.dispose();
		}
	}
}
