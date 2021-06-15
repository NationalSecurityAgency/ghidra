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
package agent.gdb.manager.impl;

import java.util.*;

import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

/**
 * Information about a GDB frame
 * 
 * <p>
 * The contains the semantic processing for GDB frame information.
 * 
 * <p>
 * Note this is not a handle to the frame. Rather, this is the captured information from some event
 * or request. If other commands have been executed since this information was gathered, the
 * information may be stale.
 */
public class GdbFrameInfo {

	/**
	 * Process a parsed GDB frame information
	 * 
	 * @param info the parsed information block
	 * @return the processed GDB frame information
	 */
	public static GdbFrameInfo parseInfo(GdbMiFieldList info) {
		String level = info.getString("level");
		String addr = info.getString("addr");
		String func = info.getString("func");
		Collection<Object> arginfo = info.get("args");
		List<String> args = new ArrayList<>();
		for (Object object : arginfo) {
			if (object instanceof GdbMiFieldList) {
				args.add(((GdbMiFieldList) object).toString());
			}
		}
		return new GdbFrameInfo(level, addr, func, args);
	}

	private final String level;
	private final String addr;
	private final String func;
	private final List<String> args;

	/**
	 * Construct GDB frame information
	 * 
	 * @param level frame id
	 * @param addr the stack address
	 * @param func the enclosing function
	 * @param args the function args
	 */
	GdbFrameInfo(String level, String addr, String func, List<String> args) {
		this.level = level;
		this.addr = addr;
		this.func = func;
		this.args = args;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getLevel(), getAddr());
	}

	@Override
	public String toString() {
		return "<GdbFrameInfo level=" + getLevel() + ", addr=" + getAddr() + ">";
	}

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof GdbFrameInfo))) {
			return false;
		}
		GdbFrameInfo that = (GdbFrameInfo) obj;
		if (this.getLevel() != that.getLevel()) {
			return false;
		}
		if (this.getAddr() != that.getAddr()) {
			return false;
		}
		return true;
	}

	public String getLevel() {
		return level;
	}

	public String getAddr() {
		return addr;
	}

	public String getFunc() {
		return func;
	}

	public List<String> getArgs() {
		return args;
	}

}
