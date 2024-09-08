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

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A collection of vector matches to an (originally) queried function
 *
 */
public class SimilarityVectorResult {
	private FunctionDescription basefunc;		// The original function that was queried
	private List<VectorResult> notes;		// Vectors to which base is similar
	private int totalcount;						// Total number of functions in database matching one of these vectors

	public SimilarityVectorResult() {
		// For use with restoreXml
	}

	public SimilarityVectorResult(FunctionDescription f) {
		basefunc = f;
		notes = new ArrayList<VectorResult>();
		totalcount = 0;
	}

	public void addNotes(List<VectorResult> newnotes) {
		for (VectorResult note : newnotes) {
			totalcount += note.hitcount;
			notes.add(note);
		}
	}

	public Iterator<VectorResult> iterator() {
		return notes.iterator();
	}

	public FunctionDescription getBase() {
		return basefunc;
	}

	public int getTotalCount() {
		return totalcount;
	}

	public void sortNotes() {
		Collections.sort(notes, new Comparator<VectorResult>() {

			@Override
			public int compare(VectorResult o1, VectorResult o2) {
				return Long.compare(o1.vectorid, o2.vectorid);
			}

		});
	}

	public void saveXml(Writer write) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<simvecres");
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "id",
			basefunc.getExecutableRecord().getXrefIndex());
		SpecXmlUtils.xmlEscapeAttribute(buf, "name", basefunc.getFunctionName());
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "spaceid", basefunc.getSpaceID());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "addr", basefunc.getAddress());
		buf.append(">\n");
		write.append(buf.toString());
		Iterator<VectorResult> iter = notes.iterator();
		while (iter.hasNext()) {
			iter.next().saveXml(write);
		}
		write.append("</simvecres>\n");
	}

	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory,
		DescriptionManager qmanage, Map<Integer, ExecutableRecord> exeMap) throws LSHException {
		notes = new ArrayList<VectorResult>();
		XmlElement el = parser.start("simvecres");
		int id = SpecXmlUtils.decodeInt(el.getAttribute("id"));
		ExecutableRecord exe = exeMap.get(id);
		int spaceid = SpecXmlUtils.decodeInt(el.getAttribute("spaceid"));
		long address = SpecXmlUtils.decodeLong(el.getAttribute("addr"));
		basefunc = qmanage.findFunction(el.getAttribute("name"), spaceid, address, exe);
		totalcount = 0;
		while (parser.peek().isStart()) {
			VectorResult newnote = new VectorResult();
			newnote.restoreXml(parser, vectorFactory);
			notes.add(newnote);
			totalcount += newnote.hitcount;
		}
		parser.end();
	}

}
