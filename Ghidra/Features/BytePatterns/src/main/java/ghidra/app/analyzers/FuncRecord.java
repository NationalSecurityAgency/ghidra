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

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import generic.stl.Pair;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class FuncRecord implements Comparable<FuncRecord> {

	public long hashValue;					//A 64-bit representation of the function. This is the signature of a statically linked library function.
	public String funcName;					//The function's name.
	public Function func;					//If we have it, we may as well keep the function itself around, right?
	private static long initHash = 0x12345678;
	public ArrayList<FuncRecord> children;	//Library call graph information. What library functions does this one call?
	public ArrayList<Address> calls;		//Temporary aid to linking up the call graph.

	//Constructor for an empty record.
	public FuncRecord() {
		this.func = null;
		this.funcName = "";
		this.hashValue = FuncRecord.initHash;
		this.children = new ArrayList<FuncRecord>();
		this.calls = new ArrayList<Address>();
	}

	//Constructor for building the database. Give it a function and it sets the rest.
	public FuncRecord(Function func) throws CancelledException {
		this.func = func;
		//Symbol[] symbols = func.getProgram().getSymbolTable().getSymbols(func.getEntryPoint());
		this.funcName = func.toString();
		this.hashValue = FuncRecord.initHash;
		this.children = new ArrayList<FuncRecord>();
		this.calls = new ArrayList<Address>();

		//To calculate the signature of a function, we must hash in each instruction modulo constants.
		//This must happen in some canonical order. Choosing address order is non-canonical.
		//We choose to follow address order in each address range in the body of the function,
		//with the ranges in a depth first order of the flow of control in the function.
		Listing listo = func.getProgram().getListing();
		HashSet<AddressRange> seenRanges = new HashSet<AddressRange>();
		AddressSetView body = func.getBody();														//All the addresses within the function.
		AddressRange initRange = body.getRangeContaining(func.getEntryPoint());	//First address range.
		PriorityQueue<AddressRange> q = new PriorityQueue<AddressRange>();							//Queue of address ranges to process.
		seenRanges.add(initRange);																	//Which address ranges have been seen already.
		q.add(initRange);																			//Initialize the queue.
		FunctionManager fMan = func.getProgram().getFunctionManager();								//Needed to identify call graph info.
		MessageDigest digest = new FNV1a64MessageDigest();

		while (q.peek() != null) {														//When there are no address ranges left to process, we're done.
			AddressRange curRange = q.remove();											//This address range is being processed.
			AddressSet curView = new AddressSet(curRange);
			CodeUnitIterator units = listo.getCodeUnits(curView, true);					//Get the instructions, already laid down in the listing.
			while (units.hasNext()) {
				CodeUnit unit = units.next();
				if (!(unit instanceof Instruction)) {
					continue;
				}
				Instruction instr = (Instruction) unit;									//Instructions are code units.
				Address[] localCalls = instr.getFlows();								//Get calls to fill call graph.
				if (localCalls != null && localCalls.length > 1) {
					Arrays.sort(localCalls);											//We use order to cut down on combinatorial explosion.
				}
				if (localCalls != null) {
					for (Address call : localCalls) {
						Function possibleCall = fMan.getFunctionContaining(call);
						if (possibleCall != null && possibleCall.getEntryPoint().equals(call)) {
							this.calls.add(call);										//Prepare to fill the call graph.
						}
					}
				}
				try {
					byte[] toHash = instr.getBytes();									//At each instruction, we will "hash in" its bytes.
					for (int opNum = 0; opNum < instr.getNumOperands(); opNum++) {
						Object[] opObs = instr.getOpObjects(opNum);
						for (Object ob : opObs) {
							//We must mask off the bits corresponding to any constants, which could have changed in the static linking process.
							if (!(ob instanceof Register) && !(ob instanceof Character)) {
								byte[] mbytes =
									instr.getPrototype().getOperandValueMask(opNum).getBytes();
								for (int i = 0; i < mbytes.length; i++) {
									//Actually mask it off.
									toHash[i] = (byte) (toHash[i] & (0xff ^ mbytes[i]));
								}
							}
						}
					}

					//Create the list of bytes to be hashed.
					byte[] totalToHash = new byte[toHash.length + 8];					//It's made from toHash and a long...but in bytes!					
					//First put in the current hash (a long).
					for (int bytt = 0; bytt < 8; bytt++) {
						totalToHash[bytt] = (byte) ((this.hashValue >>> (8 * (7 - bytt))) % 256);
					}
					//Then put in the instruction bytes.
					for (int index = 0; index < toHash.length; index++) {
						totalToHash[8 + index] = toHash[index];
					}

					digest.reset();
					digest.update(totalToHash, TaskMonitorAdapter.DUMMY_MONITOR);

					//Finally, update the hash signature.
					this.hashValue = digest.digestLong();

				}
				catch (MemoryAccessException e1) {
					e1.printStackTrace();
				}

				//It's important to follow flows in order, since the hashing desperately needs a specific order to work.
				Address[] flows = instr.getFlows();
				if (flows.length > 1) {
					Arrays.sort(flows);
				}
				for (Address flow : flows) {
					AddressRange flowRange = body.getRangeContaining(flow);
					if (flowRange != null && !seenRanges.contains(flowRange)) {
						q.add(flowRange);
						seenRanges.add(flowRange);
					}
				}
			}
		}
	}

	@Override
	public String toString() {
		String result = "";
		result += this.funcName;
		result += "," + this.hashValue;
		return result;
	}

	@Override
	//Records are comparable by hash value. This makes it easier to find a record when we want to query our database for the library hash.
	public int compareTo(FuncRecord o) {
		int first = ((Long) this.hashValue).compareTo(o.hashValue);			//Compare by hash.
		if (first != 0) {
			return first;
		}
		return this.funcName.compareTo(o.funcName);					//Break ties based on function name..
	}

	//Restores a record and its children from an XML file.
	public ArrayList<Pair<String, String>> restoreXml(XmlPullParser parser) {

		//We can only read in strings, the DB object will have to reconstruct the rest.
		ArrayList<Pair<String, String>> edges = new ArrayList<Pair<String, String>>();

		XmlElement el = parser.start("funcRec");
		this.funcName = el.getAttribute("funcName");
		String hashValStr = el.getAttribute("hashVal");
		this.hashValue = Long.parseLong(hashValStr);

		//Get list of children
		while (parser.peek().isStart()) {
			XmlElement elt = parser.start("child");
			edges.add(new Pair<String, String>(funcName, elt.getAttribute("name")));
			parser.end();
		}
		parser.end();

		//Pass the string-edges back so the DB object can reconstruct the record-edges.
		return edges;
	}

	//Write out a <funcRec/> segment in XML.
	public void saveXml(Writer fwrite) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("  <funcRec");
		buf.append(" funcName=\"");
		SpecXmlUtils.xmlEscape(buf, this.funcName);
		buf.append("\"");
		buf.append(" hashVal=\"" + this.hashValue + "\"");
		buf.append(">\n");

		fwrite.append(buf.toString());

		buf = new StringBuilder();
		for (FuncRecord kid : this.children) {
			buf.append("   <child name=\"");
			SpecXmlUtils.xmlEscape(buf, kid.funcName);
			buf.append("\"/>\n");
		}
		//NB: It is unnecessary to store parents and children, since when we create the graph from the file, we can create both sides simultaneously.

		buf.append("  </funcRec>\n");
		fwrite.append(buf.toString());

		return;
	}
}
