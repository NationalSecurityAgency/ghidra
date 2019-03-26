/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package db;

public class TestSpeed {
		
	private static byte[] createBuf() {	
		byte[] buf = new byte[16*1024];
	
		for(int i=0;i<2*1024;i++) {
			putLong(buf, i, i);
		}
		return buf;
	}	
	private static void putLong(byte[] data, int index, long v) {
		int i=index*8;
		data[i+0] =   (byte) (v >> 56);
		data[i+1] = (byte) (v >> 48);
		data[i+2] = (byte) (v >> 40);
		data[i+3] = (byte) (v >> 32);		
		data[i+4] = (byte) (v >> 24);
		data[i+5] = (byte) (v >> 16);
		data[i+6] = (byte) (v >> 8);
		data[i+7] = (byte) v;
	}	
	public static void main(String[] args) {
		byte[] buf = createBuf();

		test1(buf);
		test2(buf);
	}
	private static void test1(byte[] buf) {
		JavaBinarySearcher search1 = new JavaBinarySearcher();
		int nKeys = 2048;

		long start = System.currentTimeMillis();
		for(int j=0;j<1000;j++) {
			for(int i=0;i<nKeys;i++) {
				int index = search1.binarySearch(buf, i, nKeys); 
				if (index != i) {
					System.out.println("search failed");
				}
			}
		}
		long end = System.currentTimeMillis();
		System.out.println("Done, time = "+(end-start));
	}
	private static void test2(byte[] buf) {
		JavaBinarySearcher2 search1 = new JavaBinarySearcher2();
		int nKeys = 2048;

		long start = System.currentTimeMillis();
		for(int j=0;j<1000;j++) {
			for(int i=0;i<nKeys;i++) {
				int index = search1.binarySearch(buf, i, nKeys); 
				if (index != i) {
					System.out.println("search failed");
				}
			}
		}
		long end = System.currentTimeMillis();
		System.out.println("Done, time = "+(end-start));
	}
}


class JavaBinarySearcher {
	public int binarySearch(byte[] buf, long key, int nKeys) {
		
		int min = 0;
		int max = nKeys-1;
		
		while (min <= max) {
			int i = (min + max)/2;
			long k = getKey(buf, i);
			if (k == key) {
				return i;
			}
			else if (k < key) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return -(min+1);
	}
	private long getKey(byte[] buf, int i) {
		byte[] data = get(buf, i*8);
		return (((long)data[0] & 0xff) << 56)
		| (((long)data[1] & 0xff) << 48)
		| (((long)data[2] & 0xff) << 40)
		| (((long)data[3] & 0xff) << 32)
		| (((long)data[4] & 0xff) << 24)
		| (((long)data[5] & 0xff) << 16)
		| (((long)data[6] & 0xff) << 8)
		| ((long)data[7] & 0xff);
	}
	private byte[] get(byte[] buf, int start) {
		byte[] data = new byte[8];
		for(int i=0;i<8;i++) {
			data[i] = buf[start+i];
		}
		return data;
	}
}

class JavaBinarySearcher2 {
	public int binarySearch(byte[] buf, long key, int nKeys) {
		
		int min = 0;
		int max = nKeys-1;
		
		while (min <= max) {
			int i = (min + max)/2;
			long k = getKey(buf, i);
			if (k == key) {
				return i;
			}
			else if (k < key) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return -(min+1);
	}
	private long getKey(byte[] data, int i) {
		int idx = i*8;
		return (((long)data[idx+0] & 0xff) << 56)
		| (((long)data[idx+1] & 0xff) << 48)
		| (((long)data[idx+2] & 0xff) << 40)
		| (((long)data[idx+3] & 0xff) << 32)
		| (((long)data[idx+4] & 0xff) << 24)
		| (((long)data[idx+5] & 0xff) << 16)
		| (((long)data[idx+6] & 0xff) << 8)
		| ((long)data[idx+7] & 0xff);
	}
}

