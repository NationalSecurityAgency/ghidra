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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A collection of matches to an (originally) queried function
 *
 */
public class SimilarityResult implements Iterable<SimilarityNote> {
	private FunctionDescription basefunc;	// The original function that was queried
	private List<SimilarityNote> notes;	    // Functions to which base is similar
	private int totalcount;	                // Total number of functions in database meeting similarity and significance

	public SimilarityResult() {
	}		// For use with restoreXml

	public SimilarityResult(FunctionDescription f) {
		basefunc = f;
		notes = new ArrayList<SimilarityNote>();
		totalcount = 0;
	}

	public void addNote(FunctionDescription f, double similarity, double significance) {
		notes.add(new SimilarityNote(f, similarity, significance));
	}

	public FunctionDescription getBase() {
		return basefunc;
	}

	public int size() {
		return notes.size();
	}

	public void setTotalCount(int count) {
		totalcount = count;
	}

	public int getTotalCount() {
		return totalcount;
	}

	@Override
	public Iterator<SimilarityNote> iterator() {
		return notes.iterator();
	}

	public void transfer(DescriptionManager manage, boolean transsig) throws LSHException {
		for (SimilarityNote note : notes) {
			note.transfer(manage, transsig);
		}
	}

	public void setTransfer(SimilarityResult op2, DescriptionManager qmanage,
		DescriptionManager rmanage, boolean transsig) throws LSHException {
		ExecutableRecord erec = qmanage.findExecutable(op2.basefunc.getExecutableRecord().getMd5());
		basefunc =
			qmanage.findFunction(op2.basefunc.getFunctionName(), op2.basefunc.getSpaceID(), op2.basefunc.getAddress(), erec);
		totalcount = op2.totalcount;
		notes = new ArrayList<SimilarityNote>();
		for (SimilarityNote item : op2.notes) {
			SimilarityNote newitem = new SimilarityNote();
			newitem.setTransfer(item, rmanage, transsig);
			notes.add(newitem);
		}
	}

	public void saveXml(Writer write) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<simres");
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "id",
			basefunc.getExecutableRecord().getXrefIndex());
		SpecXmlUtils.xmlEscapeAttribute(buf, "name", basefunc.getFunctionName());
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "spaceid", basefunc.getSpaceID());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "addr", basefunc.getAddress());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "total", totalcount);
		buf.append(">\n");
		write.append(buf.toString());
		Iterator<SimilarityNote> iter = notes.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(write);
		}
		write.append("</simres>\n");
	}

	public void restoreXml(XmlPullParser parser, DescriptionManager qmanage,
		DescriptionManager rmanage,
		Map<Integer, ExecutableRecord> qMap, Map<Integer, ExecutableRecord> rMap)
		throws LSHException {
		notes = new ArrayList<SimilarityNote>();
		XmlElement el = parser.start("simres");
		int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
		ExecutableRecord exe = qMap.get(id);
		int spaceid = SpecXmlUtils.decodeInt(el.getAttribute("spaceid"));
		long address = SpecXmlUtils.decodeLong(el.getAttribute("addr"));
		basefunc = qmanage.findFunction(el.getAttribute("name"), spaceid, address, exe);
		totalcount = SpecXmlUtils.decodeInt(el.getAttribute("total"));
		while (parser.peek().isStart()) {
			SimilarityNote newnote = new SimilarityNote();
			newnote.restoreXml(parser, rmanage, rMap);
			notes.add(newnote);
		}
		parser.end();
	}

	public void sortNotes() {
		Collections.sort(notes);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - base function: " + basefunc;
	}
}
