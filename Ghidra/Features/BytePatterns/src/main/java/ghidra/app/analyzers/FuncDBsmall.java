/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.TreeSet;

public class FuncDBsmall implements FuncDB<FuncRecord> {

	private TreeSet<LibraryRecord> libraries;

	//Empty Constructor
	public FuncDBsmall() {
		this.libraries = new TreeSet<LibraryRecord>();
	}

	//Construct a DB from the current program, with a record for every function.
	public FuncDBsmall(Program prgm) throws CancelledException {
		this.libraries = new TreeSet<LibraryRecord>();
		this.libraries.add(new LibraryRecord(prgm));
	}

	//Merge another DB into this one.
	public void mergeWith(FuncDBsmall toMergeIn) {
		this.libraries.addAll(toMergeIn.libraries);
	}

	//Add a library to the database.
	public void addLibrary(LibraryRecord libRec) {
		this.libraries.add(libRec);
		return;
	}

	public TreeSet<FuncRecord> getRecords() {
		TreeSet<FuncRecord> results = new TreeSet<FuncRecord>();
		for (LibraryRecord lib : this.libraries) {
			results.addAll(lib.getRecords());
		}
		return results;
	}

	//Find an entry of the database based on actual underlying function.
	@Override
	public ArrayList<FuncRecord> query(Function func) throws CancelledException {
		FuncRecord queryHash = new FuncRecord(func);
		ArrayList<FuncRecord> result = this.query(queryHash.hashValue);			//Use the hash query method instead.
		for (FuncRecord entry : result) {
			if (entry.func == func) {
				ArrayList<FuncRecord> newResult = new ArrayList<FuncRecord>();
				newResult.add(entry);
				return newResult;
			}
		}
		return result;															//Return all matches.
	}

	//Find an entry of the database based on hash.  Returns all records with that hash.
	public ArrayList<FuncRecord> query(Long hash) {
		ArrayList<FuncRecord> result = new ArrayList<FuncRecord>();				//Set up the result.
		FuncRecord temp = new FuncRecord();
		temp.hashValue = hash;
		for (LibraryRecord libRec : this.libraries) {								//Search each library for a record matching the hash.
			result.addAll(libRec.query(hash));
		}
		return result;
	}

	//DB is made up of libraries. To get a DB from a file/parser, look for the "funcDB" tag, and then pass the buck to the LibraryRecord class.
	@Override
	public void restoreXml(XmlPullParser parser) {
		parser.start("funcDB");													//The XML tag for an entire DB.
		while (parser.peek().isStart()) {
			LibraryRecord libRec = new LibraryRecord();
			libRec.restoreXml(parser);											//Pass the buck.
			this.addLibrary(libRec);											//DB is a collection of library records.
		}
		parser.end();
		return;
	}

	//Save DB to an XML file.
	@Override
	public void saveXml(Writer fwrite) throws IOException {
		StringBuffer buf = new StringBuffer();
		buf.append("<funcDB>\n");												//The XML tag for the entire DB.
		fwrite.append(buf.toString());
		for (LibraryRecord libRec : this.libraries) {
			libRec.saveXml(fwrite);												//Write out each library in XML.
		}
		fwrite.append("</funcDB>\n");											//Finish up.
		return;
	}
}
