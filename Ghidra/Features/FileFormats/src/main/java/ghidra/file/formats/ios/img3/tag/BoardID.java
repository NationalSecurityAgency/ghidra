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
package ghidra.file.formats.ios.img3.tag;

public enum BoardID {
	iPhone2G(0x0),
	iPhone3G(0x04),
	iPhone3GS(0x00),
	iPodTouch1stGen(0x02),
	iPodTouch2ndGen(0x00),
	iPodTouch3rdGen(0x02);

	private int boardID;

	private BoardID(int boardID) {
		this.boardID = boardID;
	}

	public int getBoardID() {
		return boardID;
	}
}
