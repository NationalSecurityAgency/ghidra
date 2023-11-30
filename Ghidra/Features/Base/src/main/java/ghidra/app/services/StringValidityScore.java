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
package ghidra.app.services;

/**
 * Result of a {@link StringValidatorService}'s judgment about a string.
 *
 * @param originalString string being scored
 * @param transformedString original string, after being tweaked
 * @param score string's validity score, larger values are more valid
 * @param threshold score that this string would need to exceed to be considered valid
 */
public record StringValidityScore(
		String originalString,
		String transformedString,
		double score,
		double threshold) {

	public static StringValidityScore makeDummyFor(String s) {
		return new StringValidityScore(s, s, 0, 100);
	}

	public boolean isScoreAboveThreshold() {
		return score > threshold;
	}

}
