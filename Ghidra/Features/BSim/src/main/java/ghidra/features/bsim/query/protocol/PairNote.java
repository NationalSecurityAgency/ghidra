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

import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Result of a comparison between two functions.
 * Includes descriptors for the original functions, the similarity and significance scores
 * and other score information.
 *
 */
public class PairNote {
	private ExeSpecifier exe1;
	private FunctionEntry func1;		// First function
	private ExeSpecifier exe2;
	private FunctionEntry func2;		// Second function
	private double sim;					// Similarity
	private double signif;				// Significance
	private double dotprod;				// Unnormalized dot product
	private int count1;					// Number of hashes from func1
	private int count2;					// Number of hashes from func2
	private int icount;					// Number of hashes in intersection

	public double getSimilarity() {
		return sim;
	}

	public double getSignificance() {
		return signif;
	}

	public double getDotProduct() {
		return dotprod;
	}

	public int getFunc1HashCount() {
		return count1;
	}

	public int getFunc2HashCount() {
		return count2;
	}

	public int getIntersectionCount() {
		return icount;
	}

	public PairNote() {	// For use with restoreXml
	}

	public PairNote(FunctionDescription f1,FunctionDescription f2,double sm,double sf,double dp,
					int c1,int c2,int ic) {
		exe1 = new ExeSpecifier();
		exe1.transfer(f1.getExecutableRecord());
		func1 = new FunctionEntry(f1);
		exe2 = new ExeSpecifier();
		exe2.transfer(f2.getExecutableRecord());
		func2 = new FunctionEntry(f2);
		sim = sm;
		signif = sf;
		dotprod = dp;
		count1 = c1;
		count2 = c2;
		icount = ic;
	}

	public void saveXml(Writer writer) throws IOException {
		writer.append("<note>\n");
		exe1.saveXml(writer);
		func1.saveXml(writer);
		exe2.saveXml(writer);
		func2.saveXml(writer);
		writer.append(" <sim>").append(Double.toString(sim)).append("</sim>\n");
		writer.append(" <sig>").append(Double.toString(signif)).append("</sig>\n");
		writer.append(" <dot>").append(Double.toString(dotprod)).append("</dot>\n");
		writer.append(" <cnt1>").append(Integer.toString(count1)).append("</cnt1>\n");
		writer.append(" <cnt2>").append(Integer.toString(count2)).append("</cnt2>\n");
		writer.append(" <icnt>").append(Integer.toString(icount)).append("</icnt>\n");
		writer.append("</note>\n");
	}
	
	public void restoreXml(XmlPullParser parser) {
		XmlElement startEl = parser.start("note");
		exe1 = new ExeSpecifier();
		exe1.restoreXml(parser);
		func1 = FunctionEntry.restoreXml(parser);
		exe2 = new ExeSpecifier();
		exe2.restoreXml(parser);
		func2 = FunctionEntry.restoreXml(parser);
		parser.start("sim");
		sim = Double.parseDouble(parser.end().getText());
		parser.start("sig");
		signif = Double.parseDouble(parser.end().getText());
		parser.start("dot");
		dotprod = Double.parseDouble(parser.end().getText());
		parser.start("cnt1");
		count1 = SpecXmlUtils.decodeInt(parser.end().getText());
		count2 = SpecXmlUtils.decodeInt(parser.end().getText());
		icount = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.end(startEl);
	}
}
