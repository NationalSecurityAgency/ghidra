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
package classrecovery;

public class BaseTypeinfo {
	
	GccTypeinfo baseTypeinfo;
	int baseOrder;
	boolean isPublic;
	boolean isVirtual;
	long offset;

	public BaseTypeinfo(GccTypeinfo baseTypeinfo, int baseOrder,  boolean isPublic, boolean isVirtual, long offset){
		this.baseTypeinfo = baseTypeinfo;
		this.baseOrder = baseOrder;
		this.isPublic = isPublic;
		this.isVirtual = isVirtual;
		this.offset = offset;
	}
	
	public GccTypeinfo getBaseTypeinfo() {
		return baseTypeinfo;
	}
	
	public boolean isPublicBase() {
		return isPublic;
	}
	
	public boolean isVirtualBase() {
		return isVirtual;
	}
	
	public long getOffset() {
		return offset;
	}
	
	public boolean isClassObjectOffset() {
		if(isVirtual) {
			return false;
		}
		return true;
	}
	
	public boolean isVbaseOffset() {
		if(isVirtual) {
			return true;
		}
		return false;
	}

}
