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
package ghidra.pcodeCPort.slgh_compile;

class OptimizeRecord {
	final long offset;
	final int size;
	int writeop;
	int readop;
	int inslot;
	int writecount;
	int readcount;
	int writesection;
	int readsection;
	int opttype;

	OptimizeRecord(long offset, int size) {
		this.offset = offset;
		this.size = size;

		writeop = -1;
		readop = -1;
		inslot = -1;
		writecount = 0;
		readcount = 0;
		writesection = -2;
		readsection = -2;
		opttype = -1;
	}

	public void copyFromExcludingSize(OptimizeRecord that) {
		this.writeop = that.writeop;
		this.readop = that.readop;
		this.inslot = that.inslot;
		this.writecount = that.writecount;
		this.readcount = that.readcount;
		this.writesection = that.writesection;
		this.readsection = that.readsection;
		this.opttype = that.opttype;
	}

	public void updateRead(int i, int inslot, int secNum) {
		assert inslot >= 0;
		this.readop = i;
		this.readcount += 1;
		this.inslot = inslot;
		this.readsection = secNum;
	}

	public void updateWrite(int i, int secNum) {
		this.writeop = i;
		this.writecount += 1;
		this.writesection = secNum;
	}

	public void updateExport() {
		this.writeop = 0;
		this.readop = 0;
		this.writecount = 2;
		this.readcount = 2;
		this.readsection = -2;
		this.writesection = -2;
	}

	public void updateCombine(OptimizeRecord that) {
		if (that.writecount != 0) {
			this.writeop = that.writeop;
			this.writesection = that.writesection;
		}
		if (that.readcount != 0) {
			this.readop = that.readop;
			this.inslot = that.inslot;
			this.readsection = that.readsection;
		}
		this.writecount += that.writecount;
		this.readcount += that.readcount;
		// opttype is not relevant here
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
