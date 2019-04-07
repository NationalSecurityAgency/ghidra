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
package ghidra.feature.fid.db;

import generic.hash.FNV1a64MessageDigest;
import ghidra.feature.fid.hash.FidHashQuad;

/**
 * Currently this class only contains the helper methods that calculate "hash smash"
 * values for parent/child call relationships.  See RelationsTable for more information.
 */
public class FidDBUtils {
	/**
	 * Generate the hash smash for a superior id/inferior full hash.
	 * @param superiorFunction the function in question
	 * @param inferiorFunction the callee of the function in question
	 * @return the hash "smash" of the caller id to the callee full hash
	 */
	public static long generateSuperiorFullHashSmash(FunctionRecord superiorFunction,
			FunctionRecord inferiorFunction) {
		long hashValue = superiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME; // Improve bit diversity on key
		return hashValue ^ inferiorFunction.getFullHash();
	}

	/**
	 * Generate the hash smash for a superior full hash/inferior id.
	 * @param superiorFunction the caller of the function in question
	 * @param inferiorFunction the function in question
	 * @return the hash "smash" of the caller full hash to the callee id
	 */
	public static long generateInferiorFullHashSmash(FunctionRecord superiorFunction,
			FunctionRecord inferiorFunction) {
		long hashValue = inferiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME; // Improve bit diversity on key
		return hashValue ^ superiorFunction.getFullHash();
	}

	/**
	 * Generate the hash smash for a superior id/inferior full hash.
	 * @param superiorFunction the function in question
	 * @param inferiorFunction the callee of the function in question
	 * @return the hash "smash" of the caller id to the callee full hash
	 */
	public static long generateSuperiorFullHashSmash(FunctionRecord superiorFunction,
			FidHashQuad inferiorFunction) {
		long hashValue = superiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME; // Improve bit diversity on key
		return hashValue ^ inferiorFunction.getFullHash();
	}

	/**
	 * Generate the hash smash for a superior full hash/inferior id.
	 * @param superiorFunction the caller of the function in question
	 * @param inferiorFunction the function in question
	 * @return the hash "smash" of the caller full hash to the callee id
	 */
	public static long generateInferiorFullHashSmash(FidHashQuad superiorFunction,
			FunctionRecord inferiorFunction) {
		long hashValue = inferiorFunction.getKey() * FNV1a64MessageDigest.FNV_64_PRIME; // Improve bit diversity on key
		return hashValue ^ superiorFunction.getFullHash();
	}
}
