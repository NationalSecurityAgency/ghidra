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
package ghidra.pcodeCPort.slgh_compile;

class OptimizeRecord {
	int writeop;
	int readop;
	int inslot;
	int writecount;
	int readcount;
	int writesection;
	int readsection;
	int opttype;

	OptimizeRecord() {
		writeop = -1;
		readop = -1;
		inslot = -1;
		writecount = 0;
		readcount = 0;
		writesection = -2;
		readsection = -2;
		opttype = -1;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{writeop=");
		sb.append(writeop);
		sb.append(" readop=");
		sb.append(readop);
		sb.append(" inslot=");
		sb.append(inslot);
		sb.append(" writecount=");
		sb.append(writecount);
		sb.append(" readcount=");
		sb.append(readcount);
		sb.append(" opttype=");
		sb.append(opttype);
		sb.append("}");
		return sb.toString();
	}
}
