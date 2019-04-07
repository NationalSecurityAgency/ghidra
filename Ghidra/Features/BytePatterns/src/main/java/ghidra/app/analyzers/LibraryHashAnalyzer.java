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
package ghidra.app.analyzers;

import java.io.*;
import java.util.*;

import org.xml.sax.*;

import ghidra.app.cmd.label.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

public class LibraryHashAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Library Hash Identification";
	private static final String DESCRIPTION =
		"Analyzes program for statically linked library functions (e.g., printf, scanf, etc.).";

	private final static String OPTION_NAME_MEM_SEARCH = "Analyze undefined bytes";
	private final static String OPTION_NAME_DISASSEMBLE = "Disassemble matches in undefined bytes";

	private static final String OPTION_DESCRIPTION_MEM_SEARCH =
		"Search for known library signatures in undefined bytes.";
	private static final String OPTION_DESCRIPTION_DISASSEMBLE =
		"Disassemble any library functions found while searching undefined bytes.";

	private final static boolean OPTION_DEFAULT_MEM_SEARCH = true;
	private final static boolean OPTION_DEFAULT_DISASSEMBLE = true;

	private boolean memSearchOption = OPTION_DEFAULT_MEM_SEARCH;
	private boolean disassembleOption = OPTION_DEFAULT_DISASSEMBLE;

	public LibraryHashAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPrototype();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// TODO: for now, this can't analyze anything!
		//    WARNING: this will cause this analyzer not to show up for anything!
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.identifyLibraryFunctions(set, program, monitor);
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_MEM_SEARCH, memSearchOption, null,
			OPTION_DESCRIPTION_MEM_SEARCH);
		options.registerOption(OPTION_NAME_DISASSEMBLE, disassembleOption, null,
			OPTION_DESCRIPTION_DISASSEMBLE);
	}

	/**
	 * @see ghidra.app.services.Analyzer#optionsChanged(ghidra.framework.options.Options, Program)
	 */
	@Override
	public void optionsChanged(Options options, Program program) {
		memSearchOption = options.getBoolean(OPTION_NAME_MEM_SEARCH, memSearchOption);
		disassembleOption = options.getBoolean(OPTION_NAME_DISASSEMBLE, disassembleOption);
	}

	private void identifyLibraryFunctions(AddressSetView set, Program p, TaskMonitor monitor) {
		//Get the library from the xml database file.
		File libraryFile;
		try {
			libraryFile = Application.getModuleDataFile("lib/db.xml").getFile(true);
		}
		catch (FileNotFoundException e1) {
			Msg.error(this, "Cannot find db.xml file--not hashing functions", e1);
			return;
		}

		LibHashDB db = new LibHashDB();
		//Handler is for the XML parser.
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw exception;
			}
		};

		try {
			InputStream hstream = new FileInputStream(libraryFile);
			//Create the parser.
			XmlPullParser parser = new NonThreadedXmlPullParserImpl(hstream,
				"Function Database parser", handler, false);
			hstream.close();
			//Create the database.
			db.restoreXml(parser);

			HashMap<FuncRecord, FuncRecord> pinning = new HashMap<FuncRecord, FuncRecord>(); //Matching between query and library functions.
			LibHashDB qdb = new LibHashDB(p);
			FunctionIterator funcIter = p.getListing().getFunctions(true);

			//If a signature is unique in the libraries and in the query, we may as well match them.
			while (funcIter.hasNext()) {
				Function func = funcIter.next();
				ArrayList<FuncRecord> libResponse = db.query(func);
				if (libResponse.size() != 1) { //Check uniqueness in libraries.
					continue;
				}
				FuncRecord libVal = libResponse.get(0);

				ArrayList<FuncRecord> queResponse = qdb.query(libVal.hashValue);
				if (queResponse.size() != 1) { //Check uniqueness in query.
					continue;
				}
				FuncRecord queVal = queResponse.get(0);

				pinning.put(queVal, libVal);
			}

			PriorityQueue<FuncRecord> q = new PriorityQueue<FuncRecord>(pinning.keySet());
			HashSet<FuncRecord> seen = new HashSet<FuncRecord>();

			while (q.size() > 0) {
				FuncRecord current = q.remove(); //A query record which is already matched.
				seen.add(current);
				Iterator<FuncRecord> qit = current.children.iterator();
				FuncRecord partner = pinning.get(current);
				Iterator<FuncRecord> lit = partner.children.iterator();
				while (qit.hasNext()) {
					FuncRecord qKid = qit.next(); //Child on the query side.
					if (!lit.hasNext()) {
						break;
					}
					FuncRecord lKid = lit.next(); //Child to match on the library side.
					//Should we add a second seen set for the lKids?
					if (qKid.hashValue != lKid.hashValue || seen.contains(qKid)) {
						continue;
					}
					//Match 'em and put 'em in the queue.
					//This little check is unnecessary, except that calls can be incorrectly disassembled.
					if (qKid.children.size() != lKid.children.size()) {
						continue;
					}
					pinning.put(qKid, lKid);
					this.addSymbol(p, qKid.func.getEntryPoint(), lKid.funcName, false);
					q.add(qKid);
				}
			}

			/*
			File outFile = new File(dataDir, "testy.txt");
			File outFile2 = new File(dataDir, "testy2.txt");
			FileWriter writer = new FileWriter(outFile);
			FileWriter writer2 = new FileWriter(outFile2);
			writer.write("Matched: "  + pinning.size() + "\n");
			writer2.write("Unmatched:\n");
			for(FuncRecord key : qdb.getRecords()){
				if(pinning.containsKey(key)){
					writer.write(key.toString() + "\n");
				}
				else{
					writer2.write(key.toString() + "\n");
				}
			}
			writer.close();
			writer2.close();
			*/

		}
		catch (Exception e) {
			e.printStackTrace();
		}

		return;
	}

	@Override
	public void analysisEnded(Program program) {
		// don't care
	}

	private void addSymbol(Program program, Address addr, String name, boolean localscope) {

		SymbolTable st = program.getSymbolTable();
		Symbol existSym = st.getPrimarySymbol(addr);

		Command cmd = null;

		if (existSym == null) { //Symbol didn't exist
			cmd = new AddLabelCmd(addr, name, localscope, SourceType.IMPORTED); //So we prepare to add it.
		}
		else if (!existSym.getName().equals(name)) { //There is a symbol there with the wrong name.
			if (existSym.getSource() == SourceType.DEFAULT || //It's got a non-smart name.
				(existSym.getSource() == SourceType.ANALYSIS &&
					existSym.getSymbolType().equals(SymbolType.FUNCTION))) {
				cmd = new RenameLabelCmd(addr, existSym.getName(), name, //Prepare to rename it.
					existSym.getParentNamespace(), SourceType.IMPORTED);
			}
			else {
				cmd = new AddLabelCmd(addr, name, localscope, SourceType.IMPORTED); //Our name is better?
			}
		}

		if (cmd != null && cmd.applyTo(program)) { //Apply the name, make sure it worked.
			Msg.debug(this, "Created symbol for library function " + name + " at address " + addr);

			Namespace space = st.getNamespace(addr);
			if (!localscope) {
				space = null;
			}

			cmd = new SetLabelPrimaryCmd(addr, name, space);
			cmd.applyTo(program);

			cmd = new DemanglerCmd(addr, name);
			if (cmd.applyTo(program)) {
				Msg.debug(this, "Demangled library function " + name);
			}

			//resolved.add(addr);
		}

		/*
		program.getBookmarkManager().setBookmark(addr, "Analysis",
				LibraryIdentificationConstants.LIB_BOOKMARK_CATEGORY, "Library function");
		if (disassembleOption) {
			PseudoDisassembler pdis = new PseudoDisassembler(program);
			// make sure it is a disassembly
			if (pdis.isValidSubroutine(addr, false)) {
				disassembleSet.addRange(addr, addr);
			}
		}
		*/
		return;
	}
}
