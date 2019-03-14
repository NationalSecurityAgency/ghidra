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

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.io.IOException;
import java.io.Writer;

public class IDFLookup {
	public class IDFEntry {
		public int hash;
		public int count;
	}
	
	private int size;			// Number of entries in table
	private int mask;
	private IDFEntry[] hashtable;
	
	private void initializeTable() {
		mask = 1;
		while(mask < size)		// Find first power of two greater than or equal to size
			mask <<= 1;
		
		mask <<= 1;
		hashtable = new IDFEntry[ mask ];
		for(int i=0;i<mask;++i) {
			hashtable[i] = new IDFEntry();
			hashtable[i].count = 0xffffffff;	// Mark all the slots as empty
		}
		
		mask -= 1;
	}
	
	public IDFLookup() {
		hashtable = null;
		mask = 0;
	}
	
	public boolean empty() {
		return (hashtable==null);
	}
	
	public int getCount(int hash) {
		if (mask==0) return 0;
		int val = hash & mask;
		IDFEntry entry = hashtable[val];
		while(entry.count != 0xffffffff) {
			if (entry.hash == hash)
				return entry.count;
			val = (val+1)&mask;
			entry = hashtable[val];
		}
		return 0;
	}
	
	public int getCapacity() {
		return mask;
	}
	
	public int getRawHash(int pos) {
		return hashtable[pos].hash;
	}
	
	public int getRawCount(int pos) {
		return hashtable[pos].count;
	}
	
	private void insertHash(int hash,int count) {
		IDFEntry entry;
		int val = hash & mask;
		for(;;) {
			entry = hashtable[val];
			if (entry.count == 0xffffffff)		// An empty slot
				break;
			val = (val+1)&mask;
		}
		entry.hash = hash;
		entry.count = count;
	}
	
	public void saveXml(Writer fwrite) throws IOException {
		if (empty()) {
			fwrite.append("<idflookup/>\n");
			return;
		}
		
		StringBuilder buf = new StringBuilder();
		buf.append("<idflookup");
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "size", size);
		buf.append(">\n");
		int sz = mask + 1;
		for(int i=0;i<sz;++i) {
			IDFEntry entry = hashtable[i];
			if (entry.count == 0xffffffff) continue;
			buf.append("<hash");
			SpecXmlUtils.encodeSignedIntegerAttribute(buf, "count", entry.count);
			buf.append('>');
			buf.append(SpecXmlUtils.encodeUnsignedInteger(entry.hash));
			buf.append("</hash>\n");
		}
		buf.append("</idflookup>\n");
		fwrite.append(buf.toString());
	}
	
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("idflookup");
		if (!el.hasAttribute("size"))
			return;			// Empty table
		size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
		initializeTable();
		while(parser.peek().isStart()) {
			XmlElement subel = parser.start("hash");
			int count = SpecXmlUtils.decodeInt(subel.getAttribute("count"));
			int hash = SpecXmlUtils.decodeInt(parser.end().getText());
			insertHash(hash,count);
		}
		
		parser.end(el);
	}

	/**
	 * Collapse IDFLookup into an int array, suitable for storage
	 * @return int[]
	 */
	public int[] toArray() {
		int count = 0;
		for(int i=0;i<hashtable.length;++i)
			if (hashtable[i].count != 0xffffffff)	// If not empty
				count += 1;							//   count it
		int[] res = new int[count * 2];
		int pos = 0;
		for(int i=0;i<hashtable.length;++i) {
			if (hashtable[i].count == 0xffffffff) continue;
			res[pos] = hashtable[i].hash;
			pos += 1;
			res[pos] = hashtable[i].count;
			pos += 1;
		}
		return res;
	}

	/**
	 * Set from an array of hash/count pairs.  Every even index is a hash, every odd index is a count
	 * @param hashCountPair is the pair array
	 */
	public void set(int[] hashCountPair) {

		size = hashCountPair.length/2;
		initializeTable();
		for(int i=0;i<hashCountPair.length;i+=2)
			insertHash(hashCountPair[i],hashCountPair[i+1]);
	}
}
