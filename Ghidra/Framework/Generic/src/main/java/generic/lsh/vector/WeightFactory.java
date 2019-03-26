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
package generic.lsh.vector;

import java.io.IOException;
import java.io.Writer;

import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class WeightFactory {
	private double idfweight[] = new double[512];		// Weights associated with (normalized) idf counts
	private double tfweight[] = new double[64];			// Weights associated with tf (term frequency) counts
	private double weightnorm;		// Scale to which idf weights are normalized = -log2( probability of 1000th most common hash)
	private double probflip0;		// Hash flipping probability in causal model, param0
	private double probflip1;		// Hash flipping probability in causal model, param1
	private double probdiff0;		// Hash addition/removal probability, param0
	private double probdiff1;		// Hash addition/removal probability, param1
	private double scale;			// Final scaling to all weights
	private double addend;			// Final correction to score
	private double probflip0_norm;
	private double probflip1_norm;
	private double probdiff0_norm;
	private double probdiff1_norm;
	
	private void updateNorms() {
		probflip0_norm = probflip0 * scale;
		probflip1_norm = probflip1 * scale;
		probdiff0_norm = probdiff0 * scale;
		probdiff1_norm = probdiff1 * scale;
	}
	
	/**
	 * @return number of weights in the IDF portion of the table
	 */
	public final int getIDFSize() {
		return idfweight.length;
	}

	/**
	 * @return number of weights in the TF portion of the table
	 */
	public final int getTFSize() {
		return tfweight.length;
	}

	/**
	 * @return number of floating-point entries needed to serialize the factory
	 */
	public final int getSize() {
		return idfweight.length + tfweight.length + 7;
	}

	/**
	 * @param val
	 * @return the IDF weight at the given position
	 */
	public final double getIDFWeight(short val) {
		return idfweight[val];
	}

	/**
	 * @param val is the term count (-1)
	 * @return the TF weight for the given count
	 */
	public final double getTFWeight(short val) {
		return tfweight[val];
	}

	/**
	 * Given an IDF position and a TF count, build the feature coefficient
	 * @param i is the IDF position
	 * @param t is the TF count
	 * @return the feature coefficient
	 */
	public final double getCoeff(short i, short t) {
		return idfweight[i] * tfweight[t];
	}

	/**
	 * @return the weight normalization factor
	 */
	public final double getWeightNorm() {
		return weightnorm;
	}

	/**
	 * @return the first feature flip penalty parameter
	 */
	public final double getFlipNorm0() {
		return probflip0_norm;
	}

	/**
	 * @return the first feature drop penalty parameter
	 */
	public final double getDiffNorm0() {
		return probdiff0_norm;
	}

	/**
	 * @return the second feature flip penalty parameter
	 */
	public final double getFlipNorm1() {
		return probflip1_norm;
	}

	/**
	 * @return the second feature drop penalty parameter
	 */
	public final double getDiffNorm1() {
		return probdiff1_norm;
	}

	/**
	 * @return the final score scaling factor
	 */
	public final double getScale() {
		return scale;
	}

	/**
	 * @return the final score addend
	 */
	public final double getAddend() {
		return addend;
	}
	
	public void setLogarithmicTFWeights() {
		double log2 = Math.log(2.0);
		for (int i = 0; i < tfweight.length; ++i) {
			tfweight[i] = Math.sqrt(1.0 + Math.log( i + 1) / log2);
		}
	}
	
	/**
	 * Serialize this object as XML to a Writer
	 * @param fwrite is the Writer
	 * @throws IOException
	 */
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<weightfactory scale=\"");
		fwrite.append(Double.toString(scale));
		fwrite.append("\" addend=\"");
		fwrite.append(Double.toString(addend));
		fwrite.append("\">\n");
		double scale_sqrt = Math.sqrt(scale);
		for (double element : idfweight) {
			fwrite.append(" <idf>");
			fwrite.append(Double.toString(element / scale_sqrt));
			fwrite.append("</idf>\n");
		}
		for (double element : tfweight) {
			fwrite.append(" <tf>");
			fwrite.append(Double.toString(element));
			fwrite.append("</tf>\n");
		}
		fwrite.append(" <weightnorm>").append(Double.toString(weightnorm * scale)).append("</weightnorm>\n");
		fwrite.append(" <probflip0>").append(Double.toString(probflip0)).append("</probflip0>\n");
		fwrite.append(" <probflip1>").append(Double.toString(probflip1)).append("</probflip1>\n");
		fwrite.append(" <probdiff0>").append(Double.toString(probdiff0)).append("</probdiff0>\n");
		fwrite.append(" <probdiff1>").append(Double.toString(probdiff1)).append("</probdiff1>\n");
		fwrite.append("<weightfactory>\n");
	}

	/**
	 * Condense weight table down to array of doubles
	 * @return array of doubles
	 */
	public double[] toArray() {
		int numrows = getSize();
		double[] res = new double[ numrows ];
		double scaleSqrt = Math.sqrt(scale);

		for (int i = 0; i < idfweight.length; ++i) {
			res[i] = idfweight[i] / scaleSqrt;
		}

		for (int i = 0; i < tfweight.length; ++i) {
			res[i + idfweight.length] = tfweight[i];
		}

		res[numrows - 7] = weightnorm * scale;
		res[numrows - 6] = probflip0;
		res[numrows - 5] = probflip1;
		res[numrows - 4] = probdiff0;
		res[numrows - 3] = probdiff1;
		res[numrows - 2] = scale;
		res[numrows - 1] = addend;

		return res;
	}

	/**
	 * Initialize the WeightTable from an array of doubles
	 * @param weightArray
	 */
	public void set(double[] weightArray) {
		int numrows = weightArray.length;
		if (numrows != getSize()) {
			throw new NumberFormatException("Not enough values in double array");
		}
		scale = weightArray[numrows - 2];
		addend = weightArray[numrows - 1];
		weightnorm = weightArray[numrows - 7] / scale;
		probflip0 = weightArray[numrows - 6];
		probflip1 = weightArray[numrows - 5];
		probdiff0 = weightArray[numrows - 4];
		probdiff1 = weightArray[numrows - 3];
		double sqrtScale = Math.sqrt(scale);
		for (int i = 0; i < idfweight.length; ++i) {
			idfweight[i] = weightArray[i] * sqrtScale;
		}
		for (int i = 0; i < tfweight.length; ++i) {
			tfweight[i] = weightArray[i + idfweight.length];
		}
		updateNorms();
	}

	/**
	 * Build (deserialize) this object from an XML stream
	 * @param parser is the XML parser
	 */
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("weightfactory");
		scale = Double.parseDouble(el.getAttribute("scale"));
		addend = Double.parseDouble(el.getAttribute("addend"));
		double scale_sqrt = Math.sqrt(scale);
		for(int i=0;i<idfweight.length;++i) {
			parser.start("idf");
			double val = Double.parseDouble(parser.end().getText());
			idfweight[i] = val * scale_sqrt;
		}
		for(int i=0;i<tfweight.length;++i) {
			parser.start("tf");
			double val = Double.parseDouble(parser.end().getText());
			tfweight[i] = val;
		}
		parser.start("weightnorm");
		weightnorm = Double.parseDouble(parser.end().getText());
		weightnorm /= scale;
		parser.start("probflip0");
		probflip0 = Double.parseDouble(parser.end().getText());
		parser.start("probflip1");
		probflip1 = Double.parseDouble(parser.end().getText());
		parser.start("probdiff0");
		probdiff0 = Double.parseDouble(parser.end().getText());
		parser.start("probdiff1");
		probdiff1 = Double.parseDouble(parser.end().getText());
		
		parser.end(el);
		updateNorms();
	}
}
