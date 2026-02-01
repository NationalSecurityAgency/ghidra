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
import java.util.ArrayList;
import java.util.List;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.LSHException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * A list of records (PairNote) each describing the comparison of a pair of functions on the server
 * This response also includes various statistics (counts and averages) on the results
 *
 */
public class ResponsePair extends QueryResponseRecord {

	public double averageSim;			// Average similarity of pairs
	public double simStdDev;			// Similarity standard deviation
	public double averageSig;			// Average significance of pairs
	public double sigStdDev;			// Significance standard deviation
	public double scale;				// Weight table scale used in comparison
	public int pairCount;				// Valid pairs
	public int missedExe;				// Number of executables that could not be resolved
	public int missedFunc;				// Number of functions that could not be resolved
	public int missedVector;			// Number of functions without a vector to compare
	public List<PairNote> notes;

	public static class Accumulator {
		public double sumSim = 0.0;
		public double sumSimSquare = 0.0;
		public double sumSig = 0.0;
		public double sumSigSquare = 0.0;
		public int missedExe = 0;
		public int missedFunc = 0;
		public int missedVector = 0;
		public int pairCount = 0;

		/**
		 * Accumulate from already summarized statistics in a ResponsePair
		 * This method can be called multiple times to aggregate responses from multiple ResponsePairs
		 * @param responsePair to be merged
		 */
		public void merge(ResponsePair responsePair) {
			pairCount += responsePair.pairCount;
			missedExe += responsePair.missedExe;
			missedFunc += responsePair.missedFunc;
			missedVector += responsePair.missedVector;
			sumSim += responsePair.averageSim * responsePair.pairCount;
			sumSig += responsePair.averageSig * responsePair.pairCount;
			double aveSimSquare = responsePair.simStdDev * responsePair.simStdDev +
				responsePair.averageSim * responsePair.averageSim;
			sumSimSquare += aveSimSquare * responsePair.pairCount;
			double aveSigSquare = responsePair.sigStdDev * responsePair.sigStdDev +
				responsePair.averageSig * responsePair.averageSig;
			sumSigSquare += aveSigSquare * responsePair.pairCount;
		}
	}

	public ResponsePair() {
		super("responsepair");
		notes = new ArrayList<PairNote>();
	}

	public void fillOutStatistics(Accumulator accumulator) {
		pairCount = accumulator.pairCount;
		averageSim = accumulator.sumSim / pairCount;
		averageSig = accumulator.sumSig / pairCount;
		simStdDev = Math.sqrt(accumulator.sumSimSquare / pairCount - averageSim * averageSim);
		sigStdDev = Math.sqrt(accumulator.sumSigSquare / pairCount - averageSig * averageSig);
		missedExe = accumulator.missedExe;
		missedFunc = accumulator.missedFunc;
		missedVector = accumulator.missedVector;
	}

	public void saveXmlTail(Writer fwrite) throws IOException {
		fwrite.append(" <avesim>").append(Double.toString(averageSim)).append("</avesim>\n");
		fwrite.append(" <simstddev>").append(Double.toString(simStdDev)).append("</simstddev>\n");
		fwrite.append(" <avesig>").append(Double.toString(averageSig)).append("</avesig>\n");
		fwrite.append(" <sigstddev>").append(Double.toString(sigStdDev)).append("</sigstddev>\n");
		fwrite.append(" <scale>").append(Double.toString(scale)).append("</scale>\n");
		fwrite.append(" <paircount>").append(Integer.toString(pairCount)).append("</paircount>\n");
		fwrite.append(" <missedexe>").append(Integer.toString(missedExe)).append("</missedexe>\n");
		fwrite.append(" <missedfunc>")
			.append(Integer.toString(missedFunc))
			.append("</missedfunc>\n");
		fwrite.append(" <missedvector>")
			.append(Integer.toString(missedVector))
			.append(
				"</missedvector>\n");
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append('<').append(name).append(">\n");
		for (PairNote note : notes) {
			note.saveXml(fwrite);
		}
		saveXmlTail(fwrite);
		fwrite.append("</").append(name).append(">\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory)
		throws LSHException {
		XmlElement startEl = parser.start(name);
		for (;;) {
			XmlElement note = parser.peek();
			if (!note.isStart()) {
				break;
			}
			if (!note.getName().equals("note")) {
				break;
			}
			PairNote pairNote = new PairNote();
			pairNote.restoreXml(parser);
			notes.add(pairNote);
		}
		parser.start("avesim");
		averageSim = Double.parseDouble(parser.end().getText());
		parser.start("simstddev");
		simStdDev = Double.parseDouble(parser.end().getText());
		parser.start("avesig");
		averageSig = Double.parseDouble(parser.end().getText());
		parser.start("sigstddev");
		sigStdDev = Double.parseDouble(parser.end().getText());
		parser.start("scale");
		scale = Double.parseDouble(parser.end().getText());
		parser.start("paircount");
		pairCount = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("missedexe");
		missedExe = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("missedfunc");
		missedFunc = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.start("missedvector");
		missedVector = SpecXmlUtils.decodeInt(parser.end().getText());
		parser.end(startEl);
	}

}
