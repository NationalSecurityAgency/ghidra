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
package generic.lsh;

public enum LSHMemoryModel {
	SMALL("Small (slower)", 10, 0.97, 0.75),
	MEDIUM("Medium", 13, 0.97, 0.75),
	LARGE("Large (faster)", 16, 0.97, 0.75);

	private String label;
	//k = #of hyperplanes comprising the each binning.
	private int k;
	private double probabilityThreshold;
	private double tauBound;

	private LSHMemoryModel(String label, int k, double probabilityThreshold, double tauBound) {
		this.label = label;
		this.k = k;
		this.probabilityThreshold = probabilityThreshold;
		this.tauBound = tauBound;
	}

	public String getLabel() {
		return label;
	}

	public int getK() {
		return k;
	}

	public double getProbabilityThreshold() {
		return probabilityThreshold;
	}

	public double getTauBound() {
		return tauBound;
	}

	@Override
	public String toString() {
		return label;
	}
}
