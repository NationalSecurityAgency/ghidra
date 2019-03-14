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
package ghidra.pcodeCPort.sleigh;


public class ByteBufferPtr {
	private final byte[] buffer;
	private final int index;
	public ByteBufferPtr( byte[] buffer, int index ) {
		this.index = index;
		this.buffer = buffer;
	}
	public ByteBufferPtr add(int offset) {
		return new ByteBufferPtr(buffer, index+offset);
	}
	public int get( int i ) {
		return buffer[index+i];
	}
}
