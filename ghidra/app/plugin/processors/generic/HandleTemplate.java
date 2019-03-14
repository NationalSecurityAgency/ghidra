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
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.pcode.Varnode;

import java.io.Serializable;
import java.util.HashMap;

/**
 * 
 */
public class HandleTemplate implements Serializable {
//	private String name;
	private VarnodeTemplate ptr;		// pointer to data
	private ConstantTemplate space;	// space to which ptr points.
	private ConstantTemplate size;		// size in bytes of data to which ptr points.

	public HandleTemplate(ConstantTemplate sp, VarnodeTemplate p, ConstantTemplate sz) {
		space = sp;
		ptr = p;
		size = sz;
	}


	/**
	 * Method resolve.
	 * @param handles
	 * @return HandleTemplate
	 */
	public Handle resolve(HashMap<Object, Handle> handles, Position position, int off) throws Exception {
		Varnode v = ptr.resolve(handles, position, off);
		int sp = (int) space.resolve(handles, position, off);
		int sz = (int) size.resolve(handles, position, off);
		return new Handle(v,sp,sz);
	}


	/**
	 * @param position
	 * @param off
	 * @return
	 */
	public Handle resolve(Position position, int off) throws Exception {
		Varnode v = ptr.resolve(position, off);
		int sp = (int) space.resolve(position, off);
		int sz = (int) size.resolve(position, off);
		return new Handle(v,sp,sz);
	}

}
