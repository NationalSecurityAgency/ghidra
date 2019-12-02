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
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;

import generic.hash.SimpleCRC32;
import ghidra.xml.XmlPullParser;

public class LSHCosineVector implements LSHVector {
	private static final HashEntry[] EMPTY = new HashEntry[0];

	private HashEntry[] hash = EMPTY;// Sorted list of hash values and their counts
	private double length;// Length of vector
	private int hashcount;// Total number of hashes (counting multiplicity)

	public LSHCosineVector() {// For use as a template
		length = 0.0;
		hashcount = 0;
	}

	/**
	 * Install a set of features as an int[].   Each integer is a hash.  The integers MUST already be sorted.
	 * The same integer can occur more than once in the array (term frequency (TF) &gt; 1).
	 * Weights are determined by TF and Inverse Document Frequency (IDF) of individual features
	 * @param feature is the sorted array of integer hashes
	 * @param wfactory is the container of weighting information
	 * @param idflookup is the container of IDF information
	 */
	public LSHCosineVector(int[] feature,WeightFactory wfactory,IDFLookup idflookup) {
		installFeatures(feature,wfactory,idflookup);
		calcLength();
	}

	/**
	 * Uses the existing {@link #calcUniqueHash()} method to determine hash value.
	 * 
	 * @return
	 */
	@Override
	public int hashCode() {
		return (int) calcUniqueHash();
	}

	/**
	 * Eclipse-generated equals method.  Only the hash attribute is necessary.
	 * 
	 * @param obj
	 * @return
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof LSHCosineVector)) {
			return false;
		}
		LSHCosineVector other = (LSHCosineVector) obj;
		if (!Arrays.equals(hash, other.hash)) {
			return false;
		}
		return true;
	}

	/**
	 * Install hashes and weights directly.  Length is automatically calculated.
	 * The entries must already be sorted on the hash
	 * @param entries
	 */
	public void setHashEntries(HashEntry[] entries) {
		hash = entries;
		calcLength();
	}

	private void calcLength() {
		length = 0.0;
		hashcount = 0;
		for (int i = 0; i < hash.length; ++i) {
			if (hash[i] == null) {
				continue;
			}
			double coeff = hash[i].getCoeff();
			length += coeff * coeff;
			hashcount += hash[i].getTF();
		}
		length = Math.sqrt(length);
	}

	/**
	 * Assuming -feature- is sorted and -hash- is empty, count the features and populate -hash- and -tf-
	 * For every unique feature, look up its idf via -idflookup-
	 * @param feature is the list of sorted hash features
	 * @param wfactory is the WeightFactory used to decide feature weights
	 * @param idflookup is the IDFLookup used to decide relative frequency of individual features
	 */
	private void installFeatures(int[] feature,WeightFactory wfactory,IDFLookup idflookup) {
		if (feature.length == 0) {
			return;// No features
		}
		int lasthash = feature[0];
		int idf;
		int count = 1;
		int sz = 1;
		for (int i = 0; i < feature.length; ++i) {
			if (feature[i] != lasthash) {
				lasthash = feature[i];
				sz += 1;
			}
		}
		hash = new HashEntry[sz];
		lasthash = feature[0];
		sz = 0;
		if (!idflookup.empty()) {
			idf = idflookup.getCount(lasthash);

			for (int i = 1; i < feature.length; ++i) {
				int featurei = feature[i];
				if (featurei != lasthash) {
					hash[sz] = new HashEntry(lasthash, count, idf, wfactory);
					sz += 1;
					lasthash = featurei;
					count = 1;
					idf = idflookup.getCount(lasthash);
				}
				else {
					count += 1;
				}
			}
		}
		else {
			idf = 0;
			for (int i = 1; i < feature.length; ++i) {
				int featurei = feature[i];
				if (featurei != lasthash) {
					hash[sz] = new HashEntry(lasthash, count, idf, wfactory);
					sz += 1;
					lasthash = featurei;
					count = 1;
				}
				else {
					count += 1;
				}
			}
		}
		hash[sz] = new HashEntry(lasthash, count, idf, wfactory);
	}

	@Override
	public int numEntries() {
		return hash.length;
	}

	@Override
	public HashEntry getEntry(int i) {
		return hash[i];
	}

	@Override
	public HashEntry[] getEntries() {
		return hash;
	}

	@Override
	public double compare(LSHVector op2, VectorCompare data) {
		int iter, enditer, iter2, enditer2;
		LSHCosineVector op = (LSHCosineVector) op2;

		iter = 0;
		enditer = hash.length;
		iter2 = 0;
		enditer2 = op.hash.length;

		double res = 0.0;
		int intersectcount = 0;
		int hash1, hash2;
		if ((iter != enditer) && (iter2 != enditer2)) {
			hash1 = hash[iter].getHash();
			hash2 = op.hash[iter2].getHash();
			for (;;) {
				if (hash1 == hash2) {
					int t1 = hash[iter].getTF();
					int t2 = op.hash[iter2].getTF();
					if (t1 < t2) {
						double w1 = hash[iter].getCoeff();
						res += w1 * w1;
						intersectcount += t1;
					}
					else {
						double w2 = op.hash[iter2].getCoeff();
						res += w2 * w2;
						intersectcount += t2;
					}
					++iter;
					++iter2;
					if (iter == enditer) {
						break;
					}
					if (iter2 == enditer2) {
						break;
					}
					hash1 = hash[iter].getHash();
					hash2 = op.hash[iter2].getHash();
				}
				else if (hash1 + 0x80000000 < hash2 + 0x80000000) {// This needs to be an UNSIGNED comparison of hash1 and hash2
					++iter;
					if (iter == enditer) {
						break;
					}
					hash1 = hash[iter].getHash();
				}
				else {// hash1 > hash2
					++iter2;
					if (iter2 == enditer2) {
						break;
					}
					hash2 = op.hash[iter2].getHash();
				}
			}
			data.dotproduct = res;
			res /= (length * op.length);
		}
		else {
			data.dotproduct = res;
		}
		data.intersectcount = intersectcount;
		data.acount = hashcount;
		data.bcount = op.hashcount;
		return res;
	}

	@Override
	public void compareCounts(LSHVector op2, VectorCompare data) {
		int iter, enditer, iter2, enditer2;
		LSHCosineVector op = (LSHCosineVector) op2;

		iter = 0;
		enditer = hash.length;
		iter2 = 0;
		enditer2 = op.hash.length;

		int intersectcount = 0;
		int hash1, hash2;
		if ((iter != enditer) && (iter2 != enditer2)) {
			hash1 = hash[iter].getHash();
			hash2 = op.hash[iter2].getHash();
			for (;;) {
				if (hash1 == hash2) {
					int t1 = hash[iter].getTF();
					int t2 = op.hash[iter2].getTF();
					intersectcount += (t1 < t2) ? t1 : t2;
					++iter;
					++iter2;
					if (iter == enditer) {
						break;
					}
					if (iter2 == enditer2) {
						break;
					}
					hash1 = hash[iter].getHash();
					hash2 = op.hash[iter2].getHash();
				}
				else if (hash1 + 0x80000000 < hash2 + 0x80000000) {// This needs to be an UNSIGNED comparison of hash1 and hash2
					++iter;
					if (iter == enditer) {
						break;
					}
					hash1 = hash[iter].getHash();
				}
				else {// hash1 > hash2
					++iter2;
					if (iter2 == enditer2) {
						break;
					}
					hash2 = op.hash[iter2].getHash();
				}
			}
		}
		data.intersectcount = intersectcount;
		data.acount = hashcount;
		data.bcount = op.hashcount;
	}

	private void writeOnlyList(ArrayList<HashEntry> only, StringBuilder buf) {
		for (int i = 0; i < only.size(); ++i) {
			HashEntry entry = only.get(i);
			buf.append(Integer.toHexString(entry.getHash()));
			buf.append(' ').append(entry.getTF());
			buf.append(' ').append(entry.getCoeff());
			buf.append('\n');
		}
	}

	private void writeBothList(ArrayList<HashEntry> both, StringBuilder buf) {
		for (int i = 0; i < both.size(); i += 2) {
			HashEntry entry1 = both.get(i);
			HashEntry entry2 = both.get(i + 1);
			buf.append(Integer.toHexString(entry1.getHash()));
			buf.append(" (").append(entry1.getTF()).append(',').append(entry2.getTF()).append(
				") (");
			buf.append(entry1.getCoeff()).append(',').append(entry2.getCoeff()).append(")\n");
		}
	}

	@Override
	public double compareDetail(LSHVector op2, StringBuilder buf) {
		int iter, enditer, iter2, enditer2;
		LSHCosineVector op = (LSHCosineVector) op2;

		ArrayList<HashEntry> a_only = new ArrayList<HashEntry>();
		ArrayList<HashEntry> b_only = new ArrayList<HashEntry>();
		ArrayList<HashEntry> ab_both = new ArrayList<HashEntry>();

		buf.append("lena=").append(getLength()).append('\n');
		buf.append("lenb=").append(op2.getLength()).append('\n');
		iter = 0;
		enditer = hash.length;
		iter2 = 0;
		enditer2 = op.hash.length;

		double res = 0.0;
		int intersectcount = 0;
		int hash1, hash2;
		if ((iter != enditer) && (iter2 != enditer2)) {
			hash1 = hash[iter].getHash();
			hash2 = op.hash[iter2].getHash();
			for (;;) {
				if (hash1 == hash2) {
					ab_both.add(hash[iter]);
					ab_both.add(op.hash[iter2]);
					int t1 = hash[iter].getTF();
					int t2 = op.hash[iter2].getTF();
					if (t1 < t2) {
						double w1 = hash[iter].getCoeff();
						res += w1 * w1;
						intersectcount += t1;
					}
					else {
						double w2 = op.hash[iter2].getCoeff();
						res += w2 * w2;
						intersectcount += t2;
					}
					++iter;
					++iter2;
					if (iter == enditer) {
						break;
					}
					if (iter2 == enditer2) {
						break;
					}
					hash1 = hash[iter].getHash();
					hash2 = op.hash[iter2].getHash();
				}
				else if (hash1 + 0x80000000 < hash2 + 0x80000000) {// This needs to be an UNSIGNED comparison of hash1 and hash2
					a_only.add(hash[iter]);
					++iter;
					if (iter == enditer) {
						break;
					}
					hash1 = hash[iter].getHash();
				}
				else {// hash1 > hash2
					b_only.add(op.hash[iter2]);
					++iter2;
					if (iter2 == enditer2) {
						break;
					}
					hash2 = op.hash[iter2].getHash();
				}
			}
			buf.append("dotproduct=").append(res).append('\n');
			buf.append("intersect=").append(intersectcount).append('\n');
			res /= (length * op.length);
		}
		while (iter != enditer) {
			a_only.add(hash[iter]);
			++iter;
		}
		while (iter2 != enditer2) {
			b_only.add(op.hash[iter2]);
			++iter2;
		}
		writeOnlyList(a_only, buf);
		buf.append('\n');
		writeBothList(ab_both, buf);
		buf.append('\n');
		writeOnlyList(b_only, buf);
		return res;
	}

	@Override
	public double getLength() {
		return length;
	}

	@Override
	public void restoreXml(XmlPullParser parser,WeightFactory wfactory,IDFLookup idflookup) {
		parser.start("lshcosine");
		ArrayList<HashEntry> hashlist = new ArrayList<HashEntry>();
		if (idflookup.empty()) {
			while (parser.peek().isStart()) {
				HashEntry entry = new HashEntry();
				hashlist.add(entry);
				entry.restoreXml(parser, wfactory);
			}
		}
		else {
			while (parser.peek().isStart()) {
				HashEntry entry = new HashEntry();
				hashlist.add(entry);
				entry.restoreXml(parser, wfactory, idflookup);
			}
		}
		parser.end();
		hash = new HashEntry[hashlist.size()];
		hashlist.toArray(hash);
		calcLength();// The length is not stored as part of XML
	}

	@Override
	public void restoreSQL(String sql,WeightFactory wfactory,IDFLookup idflookup) throws IOException {
		ArrayList<HashEntry> hashlist = new ArrayList<HashEntry>();
		char tok;
		int start;
		if (sql.length() < 2) {
			throw new IOException("Empty lshvector SQL");
		}
		if (sql.charAt(0) != '(') {
			throw new IOException("Missing '(' while parsing lshvector SQL");
		}
		start = 1;
		tok = sql.charAt(1);
		if (tok != ')') {
			do {
				HashEntry entry = new HashEntry();
				hashlist.add(entry);
				start = entry.restoreSQL(sql, start, wfactory, idflookup);
				tok = sql.charAt(start);
				start += 1;
			}
			while (tok == ',');
		}
		if (tok != ')') {
			throw new IOException("Missing ')' while parsing lshvector SQL");
		}
		hash = new HashEntry[hashlist.size()];
		hashlist.toArray(hash);
		calcLength();
	}

	@Override
	public void restoreBase64(Reader input,char[] buffer,WeightFactory wfactory,IDFLookup idflookup,int[] decode) throws IOException {
		ArrayList<HashEntry> hashlist = new ArrayList<HashEntry>();
		int returned;
		do {
			returned = input.read(buffer,0,112);
			for(int i=0;i<returned;i+=7) {
				HashEntry entry = new HashEntry();
				if (!entry.restoreBase64(buffer, i, decode, wfactory, idflookup))
					throw new IOException("Bad base64 encoding of LSHCosine vector");
				hashlist.add(entry);
			}
		} while( returned == 112);
		hash = new HashEntry[hashlist.size()];
		hashlist.toArray(hash);
		calcLength();
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		StringBuilder buf = new StringBuilder();
		buf.append("<lshcosine>\n");
		fwrite.append(buf.toString());
		// The length is not stored as part of XML
		for (int i = 0; i < hash.length; ++i) {
			hash[i].saveXml(fwrite);
		}
		fwrite.append("</lshcosine>\n");
	}

	@Override
	public String saveSQL() {
		StringBuilder buf = new StringBuilder();
		buf.append('(');
		if (hash.length == 0) {
			buf.append(')');
			return buf.toString();
		}
		hash[0].saveSQL(buf);
		for (int i = 1; i < hash.length; ++i) {
			buf.append(',');
			hash[i].saveSQL(buf);
		}
		buf.append(')');
		return buf.toString();
	}

	@Override
	public void saveBase64(StringBuilder buffer, char[] encoder) {
		if (hash.length == 0)
			return;
		char[] charBuf = new char[70];
		int i = 0;
		int charpos = 0;
		for (;;) {
			hash[i].saveBase64(charBuf, charpos, encoder);
			i += 1;
			charpos += 7;
			if (i >= hash.length)
				break;
			if (charpos == 70) {
				buffer.append(charBuf);
				charpos = 0;
			}
		}
		if (charpos != 0)
			buffer.append(charBuf, 0, charpos);
	}

	/* (non-Javadoc)
	 * @see ghidra.query.vector.LSHVector#calcUniqueHash()
	 */
	@Override
	public long calcUniqueHash() {
		int reg1 = 0x12CF93AB;
		int reg2 = 0xEE39B2D6;
		for (int i = 0; i < hash.length; ++i) {
			HashEntry entry = hash[i];
			int curtf = entry.getTF();
			int curhash = entry.getHash();
			int oldreg1 = reg1;
			reg1 = SimpleCRC32.hashOneByte(reg1, curtf);
			reg1 = SimpleCRC32.hashOneByte(reg1, curhash);
			reg1 = SimpleCRC32.hashOneByte(reg1, (reg2 >>> 24));
			reg2 = SimpleCRC32.hashOneByte(reg2, (oldreg1 >>> 24));
			reg2 = SimpleCRC32.hashOneByte(reg2, (curhash >>> 8));
			reg2 = SimpleCRC32.hashOneByte(reg2, (curhash >>> 16));
			reg2 = SimpleCRC32.hashOneByte(reg2, (curhash >>> 24));
		}
		long res = reg1;
		long res2 = reg2;
		res2 <<= 32;// Make sure we don't sign extend, casting from int to long
		res2 >>>= 32;
		res <<= 32;
		res |= res2;
		return res;
	}
}
