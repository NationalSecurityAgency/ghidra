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

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

public class LibraryRecord implements Comparable<LibraryRecord> {

	private TreeSet<FuncRecord> records;	//The records themselves, arranged by signature value.
	private String libName;					//The library's name.
	private String libVersion;				//Any version information if two or more libraries share their name.

	//Empty Constructor - used in restoring libraries from XML files.
	public LibraryRecord() {
		this.records = new TreeSet<FuncRecord>();
		this.libName = null;
		this.libVersion = null;
	}

	//Construct a library record for the database from the current program, with a record for every function in the library.
	public LibraryRecord(Program prgm) throws CancelledException {
		this.records = new TreeSet<FuncRecord>();
		this.libName = prgm.getName();
		this.libVersion = "1.0";

		HashMap<String, FuncRecord> nameToEntry = new HashMap<String, FuncRecord>();
		HashMap<Address, FuncRecord> addrToEntry = new HashMap<Address, FuncRecord>();
		for (Function func : prgm.getFunctionManager().getFunctions(true)) {
			FuncRecord entry = new FuncRecord(func);
			this.insert(entry);
			nameToEntry.put(func.toString(), entry);
			addrToEntry.put(entry.func.getEntryPoint(), entry);
		}
		//Children are added to records
		for (FuncRecord entry : this.records) {
			for (Address call : entry.calls) {
				entry.children.add(addrToEntry.get(call));
			}
		}
	}

	//Put a record into this library. The function must hash to something other than default.
	private void insert(FuncRecord record) {
		this.records.add(record);
		return;
	}

	public TreeSet<FuncRecord> getRecords() {
		return this.records;
	}

	//The DB calls this to find functions for each library.
	public ArrayList<FuncRecord> query(Long hash) {
		ArrayList<FuncRecord> result = new ArrayList<FuncRecord>();
		FuncRecord temp = new FuncRecord();
		temp.hashValue = hash;
		for (FuncRecord entry : this.records.tailSet(temp)) {								//Records are stored in order. Check them in such a way.
			if (entry.hashValue == hash) {												//Put them in as long as the hash is correct.
				result.add(entry);
			}
			else if (entry.hashValue > hash) {											//Strictly speaking this else if can be an else.
				break;
			}
		}
		return result;
	}

	//Restore the entire database from an XML file. It winds up as an object in memory, with a FuncRecord object for each record.
	public void restoreXml(XmlPullParser parser) {
		ArrayList<Pair<String, String>> strEdges = new ArrayList<Pair<String, String>>();	//A list of the edges (in string form) recovered from XML
		HashMap<String, FuncRecord> str2rec = new HashMap<String, FuncRecord>();		//Dictionary for finding records given strings.

		XmlElement el = parser.start("libRec");
		this.libName = el.getAttribute("libName");
		this.libVersion = el.getAttribute("libVersion");
		while (parser.peek().isStart()) {
			FuncRecord entry = new FuncRecord();										//Make an entry.
			ArrayList<Pair<String, String>> edges = entry.restoreXml(parser);			//Populate the entry and find edges to reconstruct the call graph.
			str2rec.put(entry.funcName, entry);											//Add to the string->record dictionary.
			strEdges.addAll(edges);														//Keep track of edges we've seen.
			this.insert(entry);															//Put the new entry into the database.
		}

		//Recreate call graph from the edges in string form.
		for (Pair<String, String> edge : strEdges) {
			FuncRecord source = str2rec.get(edge.first);
			FuncRecord dest = str2rec.get(edge.second);
			source.children.add(dest);
		}
		parser.end();
		return;
	}

	//Put the database into a single XML file.
	public void saveXml(Writer fwrite) throws IOException {
		//Create the LibraryRecord header and attributes.
		StringBuilder buf = new StringBuilder();
		buf.append(" <libRec");
		buf.append(" libName=\"");
		SpecXmlUtils.xmlEscape(buf, this.libName);
		buf.append("\"");
		buf.append(" libVersion=\"");
		SpecXmlUtils.xmlEscape(buf, this.libVersion);
		buf.append("\">\n");

		fwrite.append(buf.toString());
		for (FuncRecord entry : this.records) {					//Save the records in the XML file.
			entry.saveXml(fwrite);								//XMLize the records.
		}
		fwrite.append(" </libRec>\n");
	}

	@Override
	//Records are comparable by hash value. This makes it easier to find a record when we want to query our database for the library hash.
	public int compareTo(LibraryRecord o) {
		int first = this.libName.compareTo(o.libName);			//Compare by hash.
		if (first != 0) {
			return first;
		}
		return this.libVersion.compareTo(o.libVersion);			//Break ties based on function name..
	}
}
