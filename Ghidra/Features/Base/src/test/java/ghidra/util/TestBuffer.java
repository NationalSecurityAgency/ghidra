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
package ghidra.util;

import java.nio.ByteBuffer;
import java.util.Date;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class TestBuffer {
	private static final int SIZE = 1000000;
	private static final int LOOPS = 100;
	byte[] data;
	
	public TestBuffer(int size) {
		data = new byte[size*4];	
	}
	public void put(int index, int value) {
		byte a = (byte)(value >> 24);
		byte b = (byte)(value >> 16);	
		byte c = (byte)(value >> 8);
		byte d = (byte)value;
		int i = index*4;
		data[i] = a;
		data[i+1] = b;
		data[i+2] = c;
		data[i+3] = d;
	}
	public int get(int index) {
		int i = index*4;
		int a = data[i] << 24;
		int b = (data[i+1] << 16) & 0x00ff0000;
		int c = (data[i+2] << 8) & 0x0000ff00;
		int d = data[i+3] & 0x000000ff;
		return a | b | c | d;
	}
		
	
	public static void main(String[] args) {
		long t = new Date().getTime();
		System.out.println("start");
		TestBuffer b = new TestBuffer(SIZE);
		for(int j = 0;j<LOOPS;j++) {
			for(int i=0;i<SIZE;i++) {
				b.put(i, i);
			}
			for(int i=0;i<SIZE;i++) {
				if (b.get(i) != i) {
					System.out.println("expected "+i+" but got "+b.get(i));
				}
			}
		}
		
		System.out.println("done");
		System.out.println("time = "+(new Date().getTime() - t));
		t = new Date().getTime();
		int[] d = new int[SIZE];

		for(int j = 0;j<LOOPS;j++) {
			for(int i=0;i<SIZE;i++) {
				d[i] = i;
			}
			for(int i=0;i<SIZE;i++) {
				if (d[i] != i) {
					System.out.println("expected "+i+" but got "+d[i]);
				}
			}
		}
		System.out.println("done 2");
		System.out.println("time = "+(new Date().getTime() - t));
		t = new Date().getTime();
		
		ByteBuffer bb = ByteBuffer.allocate(SIZE*4);

		for(int j = 0;j<LOOPS;j++) {
			for(int i=0;i<SIZE;i++) {
				bb.putInt(i<<2, i);
			}
			for(int i=0;i<SIZE;i++) {
				if (bb.getInt(i<<2) != i) {
					System.out.println("expected "+i+" but got "+bb.get(i*4));
				}
			}
		}
		System.out.println("done 3");
		System.out.println("time = "+(new Date().getTime() - t));
		
	}

}
