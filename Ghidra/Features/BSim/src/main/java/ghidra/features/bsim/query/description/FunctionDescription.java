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
package ghidra.features.bsim.query.description;

import java.io.*;
import java.util.*;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class FunctionDescription implements Comparable<FunctionDescription> {
	private final ExecutableRecord exerec;
	private final String function_name; // Name of the function (unique within the executable)
	private final long address; // Address offset of this function within its executable or -1 for a library function 
	private SignatureRecord sigrec;
	private List<CallgraphEntry> callrec;
	private RowKey id; // table id of this description
	private long vectorid; // vectorid of signature associated with this function
	private int flags; // 1-bit attributes of the function

	public static class Update {
		public FunctionDescription update;
		public boolean function_name; // Do we update the function name
		public boolean flags; // Do we update the flags
	}

	public FunctionDescription(ExecutableRecord ex, String name, long addr) {
		exerec = ex;
		function_name = name;
		sigrec = null;
		id = null;
		vectorid = 0;
		address = addr;
		flags = 0;
		callrec = null;
	}

	void setId(RowKey i) {
		id = i;
	}

	void setVectorId(long i) {
		vectorid = i;
	}

	void setFlags(int fl) {
		flags = fl;
	}

	void insertCall(FunctionDescription fd, int lhash) {
		if (callrec == null) {
			callrec = new ArrayList<CallgraphEntry>();
		}
		callrec.add(new CallgraphEntry(fd, lhash));
	}

	public void setSignatureRecord(SignatureRecord srec) {
		sigrec = srec;
	}

	public String getFunctionName() {
		return function_name;
	}

	public ExecutableRecord getExecutableRecord() {
		return exerec;
	}

	public SignatureRecord getSignatureRecord() {
		return sigrec;
	}

	public List<CallgraphEntry> getCallgraphRecord() {
		return callrec;
	}

	public RowKey getId() {
		return id;
	}

	public long getVectorId() {
		return vectorid;
	}

	public long getAddress() {
		return address;
	}

	public int getFlags() {
		return flags;
	}

	@Override
	public boolean equals(Object obj) {
		FunctionDescription o = (FunctionDescription) obj;
		int comp = exerec.compareTo(o.exerec);
		if (comp != 0) {
			return false;
		}
		comp = function_name.compareTo(o.function_name);
		if (comp != 0) {
			return false;
		}
		comp = Long.compareUnsigned(address, o.address);
		return (comp == 0);
	}

	@Override
	public int hashCode() {
		int val = (int) (address >> 32) + exerec.hashCode();
		val *= 151;
		val ^= function_name.hashCode();
		val *= 13;
		val ^= (int) address;
		return val;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " " + function_name + " (" + exerec.getNameExec() + ")";
	}

	@Override
	public int compareTo(FunctionDescription o) {
		int comp = exerec.compareTo(o.exerec);
		if (comp != 0) {
			return comp;
		}
		comp = function_name.compareTo(o.function_name);
		if (comp != 0) {
			return comp;
		}
		comp = Long.compareUnsigned(address, o.address);
		return comp;
	}

	public void sortCallgraph() {
		if ((callrec == null) || (callrec.size() < 2)) {
			return; // Nothing to do
		}
		Collections.sort(callrec);
		// dedup the list
		int i = 1;
		for (int j = 1; j < callrec.size(); ++j) {
			FunctionDescription callrecj = callrec.get(j).getFunctionDescription();
			FunctionDescription callrecjm = callrec.get(j - 1).getFunctionDescription();
			if (callrecj != callrecjm) { // Compare as pointers
				if (i != j) {
					callrec.set(i, callrec.get(j));
				}
				i += 1;
			}
		}
		if (i != callrec.size()) {
			for (int j = callrec.size() - 1; j >= i; --j) {
				callrec.remove(j);
			}
		}
	}

	public String printRaw() {
		StringBuilder buf = new StringBuilder();
		buf.append(function_name);
		buf.append(' ');
		buf.append(exerec.printRaw());
		return buf.toString();
	}

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<fdesc name=\"");
		SpecXmlUtils.xmlEscapeWriter(fwrite, function_name);
		if (address != -1) {
			fwrite.append("\" addr=\"0x").append(Long.toHexString(address));
		}
		if ((sigrec != null) && (sigrec.getCount() > 0)) {
			fwrite.append("\" sigdup=\"");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(sigrec.getCount()));
		}
		fwrite.append("\">\n");
		if (sigrec != null) {
			sigrec.saveXml(fwrite);
		}
		if (callrec != null) {
			for (CallgraphEntry element : callrec) {
				element.saveXml(this, fwrite);
			}
		}
		if (flags != 0) {
			fwrite.append("<flags>");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(flags));
			fwrite.append("</flags>\n");
		}
		fwrite.append("</fdesc>\n");
	}

	/**
	 * Update the boolean fields in -res- to true, for every field in -this- that needs to be updated from -fromDB-
	 * @param res stores the boolean results for which fields to update
	 * @param fromDB is the metadata to compare with -this- to decided if updates are necessary
	 * @return true if one or more updates is necessary
	 */
	public boolean diffForUpdate(Update res, FunctionDescription fromDB) {
		res.function_name = !function_name.equals(fromDB.function_name);
		flags = (0xfffffff9 & flags) | (fromDB.flags & 6); // keep bits 1 and 2 of database flags
		res.flags = (flags != fromDB.flags);
		id = fromDB.id;
		res.update = this;
		return res.function_name || res.flags;
	}

	static public FunctionDescription restoreXml(XmlPullParser parser,
			LSHVectorFactory vectorFactory, DescriptionManager man, ExecutableRecord erec)
			throws LSHException {
		int count = 0;
		XmlElement el = parser.start("fdesc");
		String fname = el.getAttribute("name");
		String addrString = el.getAttribute("addr");
		String sigdupstr = el.getAttribute("sigdup");
		long address = -1;			// Default value if no attribute present
		if (addrString != null) {
			address = SpecXmlUtils.decodeLong(addrString);
		}
		if (sigdupstr != null) {
			count = SpecXmlUtils.decodeInt(sigdupstr);
		}
		FunctionDescription fdesc = man.newFunctionDescription(fname, address, erec);
		if (parser.peek().isStart()) {
			if (parser.peek().getName().equals("lshcosine")) {
				SignatureRecord.restoreXml(parser, vectorFactory, man, fdesc, count);
			}
			while (parser.peek().isStart()) {
				String nm = parser.peek().getName();
				if (nm.equals("flags")) {
					parser.start();
					int flags = SpecXmlUtils.decodeInt(parser.end().getText());
					fdesc.flags = flags;
				}
				else { // Assume it is a callgraph entry
					CallgraphEntry.restoreXml(parser, man, fdesc);
				}
			}
		}
		parser.end();
		return fdesc;
	}

	/**
	 * Create a map from addresses to functions
	 * @param iter is the list of functions to map
	 * @return the Map
	 */
	public static Map<Long, FunctionDescription> createAddressToFunctionMap(
			Iterator<FunctionDescription> iter) {
		TreeMap<Long, FunctionDescription> addrmap = new TreeMap<Long, FunctionDescription>();
		while (iter.hasNext()) {
			FunctionDescription func = iter.next();
			long addr = func.getAddress();
			if (addr == -1) {
				continue;
			}
			addrmap.put(addr, func);
		}
		return addrmap;
	}

	/**
	 * Match new functions to old functions via the address, test if there is an update between the two functions,
	 * generate an update record if there is, return the list of updates
	 * @param iter is the list of NEW functions
	 * @param addrMap is a map from address to OLD functions
	 * @param badList is a container for new functions that could not be mapped to old
	 * @return the list of Update records
	 */
	public static List<Update> generateUpdates(Iterator<FunctionDescription> iter,
			Map<Long, FunctionDescription> addrMap, List<FunctionDescription> badList) {
		List<FunctionDescription.Update> updateList = new ArrayList<FunctionDescription.Update>();
		Update curupdate = new Update();
		while (iter.hasNext()) {
			FunctionDescription newfunc = iter.next();
			long addr = newfunc.getAddress();
			if (addr == -1) {
				continue;
			}
			FunctionDescription oldfunc = addrMap.get(addr);
			if (oldfunc == null) {
				badList.add(newfunc); // Keep track of functions with update info which we couldn't find
				continue;
			}
			if (newfunc.diffForUpdate(curupdate, oldfunc)) { // Check if there is any change in metadata
				updateList.add(curupdate);
				curupdate = new FunctionDescription.Update();
			}
		}
		return updateList;
	}
}
