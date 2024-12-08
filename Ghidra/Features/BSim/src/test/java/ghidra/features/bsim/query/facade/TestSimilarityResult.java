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
package ghidra.features.bsim.query.facade;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Date;

import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.util.HashUtilities;

public class TestSimilarityResult extends SimilarityResult {
//	protected static Random random = new Random();

	public TestSimilarityResult(String queryFunctionName, String executableName,
			String matchFunction, long address, double significance, double confidence) {
		super(createFunctionDescription(queryFunctionName, executableName, address));
		addNote(createFunctionDescription(matchFunction, executableName, address), significance,
			confidence);
	}

	protected static FunctionDescription createFunctionDescription(String queryFunctionName,
			String executableName, long address) {
		String hash = getMd5(executableName);
		ExecutableRecord executableRecord =
			new ExecutableRecord(hash, executableName, "gcc", "x86", new Date(), null, null, null);

		FunctionDescription description =
			new FunctionDescription(executableRecord, queryFunctionName, address);
		return description;
	}

	private static String getMd5(String executableName) {
		try {
			InputStream is = new ByteArrayInputStream(executableName.getBytes());
			String hash = HashUtilities.getHash("MD5", is);
			return hash;
		}
		catch (Exception e) {
			return "";
		}
	}

//	protected static double randomDouble() {
//		return random.nextDouble();
//	}
//
//	protected static double randomDoubleUnbounded() {
//		return random.nextDouble() * random.nextInt(100);
//	}

}
