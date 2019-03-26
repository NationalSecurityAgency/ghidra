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

import ghidra.xml.XmlPullParser;

public class WeightedLSHCosineVectorFactory extends LSHVectorFactory {

	@Override
	public LSHVector buildZeroVector() {
		return new LSHCosineVector();
	}

	@Override
	public LSHVector buildVector(int[] feature) {
		return new LSHCosineVector(feature,weightFactory,idfLookup);
	}

	@Override
	public LSHVector restoreVectorFromXml(XmlPullParser parser) {
		LSHCosineVector vector = new LSHCosineVector();
		vector.restoreXml(parser, weightFactory, idfLookup);
		return vector;
	}

	@Override
	public LSHVector restoreVectorFromSql(String sql) throws IOException {
		LSHCosineVector vector = new LSHCosineVector();
		vector.restoreSQL(sql, weightFactory, idfLookup);
		return vector;
	}
}
