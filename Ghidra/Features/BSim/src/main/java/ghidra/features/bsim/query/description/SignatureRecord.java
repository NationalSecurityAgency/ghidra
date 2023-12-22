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
package ghidra.features.bsim.query.description;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Writer;

public class SignatureRecord {
	private LSHVector sigvector; // Vector of signatures
	private long vectorid; // vectorid of signature
	private int count; // Number of duplicates of this signature within the database

	public SignatureRecord(LSHVector v) {
		sigvector = v;
		vectorid = 0;
		count = 0;
	}

	void setVectorId(long i) {
		vectorid = i;
	}

	void setCount(int c) {
		count = c;
	}

	public LSHVector getLSHVector() {
		return sigvector;
	}

	public long getVectorId() {
		return vectorid;
	}

	public int getCount() {
		return count;
	}

	public void saveXml(Writer fwrite) throws IOException {
		sigvector.saveXml(fwrite);
	}

	public static void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory,
			DescriptionManager man, FunctionDescription fdesc, int count) {
		SignatureRecord srec = man.newSignature(parser, vectorFactory, count);
		man.attachSignature(fdesc, srec);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sigvector == null) ? 0 : sigvector.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof SignatureRecord)) {
			return false;
		}
		SignatureRecord other = (SignatureRecord) obj;
		if (sigvector == null) {
			if (other.sigvector != null) {
				return false;
			}
		}
		else if (!sigvector.equals(other.sigvector)) {
			return false;
		}
		return true;
	}

}
