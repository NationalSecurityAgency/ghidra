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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.program.model.address.AddressFactory;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 *  Placeholder for what will resolve to a Varnode instance given
 *  a specific InstructionContext
 */
public class VarnodeTpl {
	private ConstTpl space;
	private ConstTpl offset;
	private ConstTpl size;

	protected VarnodeTpl() {
	}

	public VarnodeTpl(ConstTpl space, ConstTpl offset, ConstTpl size) {
		this.space = space;
		this.offset = offset;
		this.size = size;
	}

	public ConstTpl getSpace() {
		return space;
	}

	public ConstTpl getOffset() {
		return offset;
	}

	public ConstTpl getSize() {
		return size;
	}

	public boolean isDynamic(ParserWalker walker) {
		if (offset.getType() != ConstTpl.HANDLE)
			return false;
		// Technically we should probably check all three ConstTpls
		// for dynamic handles, but in all cases, if there is any
		// dynamic piece, then the offset is dynamic
		return (walker.getFixedHandle(offset.getHandleIndex()).offset_space != null);

	}

	public boolean isRelative() {
		return (offset.getType() == ConstTpl.J_RELATIVE);
	}

	public void restoreXml(XmlPullParser parser, AddressFactory factory) {
		XmlElement el = parser.start("varnode_tpl");
		space = new ConstTpl();
		space.restoreXml(parser, factory);
		offset = new ConstTpl();
		offset.restoreXml(parser, factory);
		size = new ConstTpl();
		size.restoreXml(parser, factory);
		parser.end(el);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(space);
		sb.append('[');
		sb.append(offset);
		sb.append(':');
		sb.append(size);
		sb.append(']');

		return sb.toString();
	}
}
