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
package ghidra.feature.vt.api.main;

import java.text.DecimalFormat;
import java.text.Format;

/**
 * Class that represents a numerical score for a correlator.
 *
 */
public class VTScore implements Comparable<VTScore> {

	private static final ThreadLocal<Format> SCORE_FORMAT =
		ThreadLocal.withInitial(() -> new DecimalFormat("0.000"));

	private double score;

	public VTScore(double score) {
		this.score = round(score);
	}

	// rounds the value to the precision that will be displayed.
	private double round(double value) {
		return Double.parseDouble(SCORE_FORMAT.get().format(value));
	}

	public VTScore(String scoreAsString) {
		this.score = parseScore(scoreAsString);
	}

	private double parseScore(String scoreAsString) {
		return Double.parseDouble(scoreAsString);
	}

	public double getScore() {
		return score;
	}

	public double getLog10Score() {
		return Math.log10(score);
	}

	public String getFormattedScore() {
		return SCORE_FORMAT.get().format(score);
	}

	public String getFormattedLog10Score() {
		double log10Score = getLog10Score();
		if (Double.isNaN(log10Score)) {
			return "0.00";
		}
		else if (Double.isInfinite(log10Score)) {
			return "N/A";
		}
		return SCORE_FORMAT.get().format(log10Score);
	}

	@Override
	public int hashCode() {
		long bits = Double.doubleToLongBits(score);
		return (int) (bits ^ (bits >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		VTScore other = (VTScore) obj;
		return score == other.score;
	}

	public String toStorageString() {
		return Double.toString(score);
	}

	@Override
	public int compareTo(VTScore o) {
		if (score < o.score) {
			return -1;
		}
		else if (score > o.score) {
			return 1;
		}
		return 0;
	}

	@Override
	public String toString() {
		return getFormattedScore();
	}
}
