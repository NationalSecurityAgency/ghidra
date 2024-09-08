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

import java.io.*;
import java.util.Date;
import java.util.List;

import generic.lsh.vector.*;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.protocol.SimilarityVectorResult;
import ghidra.util.HashUtilities;
import ghidra.xml.XmlPullParser;

public class TestNearestVectorResult extends SimilarityVectorResult {

	public TestNearestVectorResult(String queryFunctionName, String executableName, int hits,
			double similarity) {
		super(createFunctionDescription(queryFunctionName, executableName));
		VectorResult vectorResult = new VectorResult(1, hits, similarity, 0d, null);
		addNotes(List.of(vectorResult));
	}

	protected static FunctionDescription createFunctionDescription(String queryFunctionName,
			String executableName) {
		String hash = getMd5(executableName);
		ExecutableRecord executableRecord =
			new ExecutableRecord(hash, executableName, "gcc", "x86", new Date(), null, null, null);

		FunctionDescription description =
			new FunctionDescription(executableRecord, queryFunctionName, 0, 0x10000);
		description.setSignatureRecord(new SignatureRecord(new TestLSHVector()));
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
	private static class TestLSHVector implements LSHVector {

		@Override
		public int numEntries() {
			return 7;
		}

		@Override
		public HashEntry getEntry(int i) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public HashEntry[] getEntries() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public double getLength() {
			return 1d + Math.random();
		}

		@Override
		public double compare(LSHVector op2, VectorCompare data) {
			return 0;
		}

		@Override
		public void compareCounts(LSHVector op2, VectorCompare data) {
		}

		@Override
		public double compareDetail(LSHVector op2, StringBuilder buf) {
			return 0;
		}

		@Override
		public void saveXml(Writer fwrite) throws IOException {
			//stub
		}

		@Override
		public String saveSQL() {
			return "";
		}

		@Override
		public void saveBase64(StringBuilder buffer, char[] encoder) {
			//stub
		}

		@Override
		public void restoreXml(XmlPullParser parser, WeightFactory weightFactory,
				IDFLookup idfLookup) {
			//stub
		}

		@Override
		public void restoreSQL(String sql, WeightFactory weightFactory, IDFLookup idfLookup)
				throws IOException {
			//stub
		}

		@Override
		public void restoreBase64(Reader input, char[] buffer, WeightFactory wfactory,
				IDFLookup idflookup, int[] decode) throws IOException {
			//stub
		}

		@Override
		public long calcUniqueHash() {
			return 0;
		}
	}
}
