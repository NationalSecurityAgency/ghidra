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
package ghidra.app.plugin.core.bento;

public class BoundedObject {

	protected Object obj;
	public Object loRep;
	public Object hiRep;
	public long loBound;
	public long hiBound;
	protected long startPos;
	protected long endPos;

	protected MappedObject mobj;

	public BoundedObject(long min) {
		this(min, Long.MAX_VALUE);
	}

	public BoundedObject(long min, long max) {
		this.obj = min;
		this.loBound = min;
		this.hiBound = max;
		this.loRep = this.loBound;
		this.hiRep = this.hiBound;
		mobj = new MappedObject(this);
	}

	public long getStart() {
		return startPos;
	}

	public void setStart(long val) {
		startPos = val;
	}

	public long getStop() {
		return endPos;
	}

	public void setStop(long val) {
		endPos = val;
	}

	public MappedObject getMappedObject() {
		return mobj;
	}

	/* The following two methods feed directly to cells in a table and, while typically
	 * rendered as String's, may be given special treatment based on their type */

	public Object getLowRep() {
		return loBound;
	}

	public Object getHiRep() {
		long end = hiBound;
		if (end == Long.MAX_VALUE) {
			return "+\u221e";
		}
		return hiBound;
	}

	public BentoRadix getDefaultRadix() {
		return BentoRadix.DEFAULT;
	}

}
