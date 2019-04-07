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
package ghidra.bitpatterns.info;

/**
 * Elements of this enum represent different types of matches for a pattern.
 */
public enum PatternMatchType {
	/**
	 * A match at the start of known function
	 */
	TRUE_POSITIVE,
	/**
	 * A match within defined code that could be a function start
	 */
	POSSIBLE_START_CODE,
	/**
	 * A match that can't be a function start due to the wrong incoming flow
	 */
	FP_WRONG_FLOW,
	/**
	 * A match that can't be a function start because it occurs within a defined instruction
	 */
	FP_MISALIGNED,
	/**
	 * A match within undefined bytes that could be a function start
	 */
	POSSIBLE_START_UNDEFINED,
	/**
	 * A match within defined data
	 */
	FP_DATA,
	/**
	 * A matc with a context register conflict
	 */
	CONTEXT_CONFLICT,
	/**
	 * A match of a pre-pattern without a post-pattern
	 */
	PRE_PATTERN_HIT
}
