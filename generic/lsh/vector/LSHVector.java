/* ###
 * IP: GHIDRA
 * NOTE: Locality Sensitive Hashing
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

import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

public interface LSHVector {

	public int numEntries();

	public HashEntry getEntry(int i);
	
	public HashEntry[] getEntries();

	public double getLength();

	public double compare(LSHVector op2,VectorCompare data);

	public void compareCounts(LSHVector op2, VectorCompare data);

	public double compareDetail(LSHVector op2, StringBuilder buf);

	public void saveXml(Writer fwrite) throws IOException;
	
	public String saveSQL();

	public void saveBase64(StringBuilder buffer,char[] encoder);

	public void restoreXml(XmlPullParser parser,WeightFactory weightFactory,IDFLookup idfLookup);
	
	public void restoreSQL(String sql,WeightFactory weightFactory,IDFLookup idfLookup) throws IOException;

	public void restoreBase64(Reader input,char[] buffer,WeightFactory wfactory,IDFLookup idflookup,int[] decode) throws IOException;

	public long calcUniqueHash();
}
