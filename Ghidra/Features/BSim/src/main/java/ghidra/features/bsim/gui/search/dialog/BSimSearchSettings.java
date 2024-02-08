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
package ghidra.features.bsim.gui.search.dialog;

/**
 * Class to hold all the settings for a BSim similar functions search
 */
public class BSimSearchSettings {
	private double similarity;
	private double confidence;
	private int maxResults;
	private BSimFilterSet filterSet;

	public BSimSearchSettings() {
		this.similarity = 0.7;
		this.confidence = 0.0;
		this.maxResults = 100;
		this.filterSet = new BSimFilterSet();
	}

	public BSimSearchSettings(double similarity, double confidence, int maxResults,
		BSimFilterSet filterSet) {
		this.similarity = similarity;
		this.confidence = confidence;
		this.maxResults = maxResults;
		this.filterSet = filterSet;
	}

	private BSimSearchSettings(BSimSearchSettings settings) {
		this.similarity = settings.similarity;
		this.confidence = settings.confidence;
		this.maxResults = settings.getMaxResults();
		this.filterSet = settings.getBSimFilterSet().copy();
	}

	/**
	 * Returns the similarity criteria.
	 * @return the similarity criteria.
	 */
	public double getSimilarity() {
		return similarity;
	}

	/**
	 * Returns the confidence criteria.
	 * @return the confidence criteria.
	 */
	public double getConfidence() {
		return confidence;
	}

	/**
	 * Returns the maximum number of matches for a single function.
	 * @return the maximum number of matches for a single function
	 */
	public int getMaxResults() {
		return maxResults;
	}

	/**
	 * Returns the filters to be used for the query
	 * @return the filters to be used for the query
	 */
	public BSimFilterSet getBSimFilterSet() {
		return filterSet;
	}

	/**
	 * Returns a copy of this settings.
	 * @return a copy of this settings.
	 */
	public BSimSearchSettings copy() {
		return new BSimSearchSettings(this);
	}

}
