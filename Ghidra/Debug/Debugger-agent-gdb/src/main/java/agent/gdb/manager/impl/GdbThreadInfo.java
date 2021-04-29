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

import java.math.BigInteger;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import ghidra.util.Msg;

/**
 * Information about a GDB thread
 */
public class GdbThreadInfo {

	protected static final Pattern TARGET_ID_LINE_PATTERN0 = Pattern.compile("\\s*" + //
		"Thread 0x(?<addr>[0-9,A-F,a-f]+)\\s+" + //
		"\\(LWP (?<tid>[0-9]+)\\)\\s*");
	protected static final Pattern TARGET_ID_LINE_PATTERN1 = Pattern.compile("\\s*" + //
		"process (?<tid>[0-9]+)\\s*");

	/**
	 * Process a parsed GDB thread information
	 * 
	 * @param info the parsed information block
	 * @return the processed GDB thread information
	 */
	public static GdbThreadInfo parseInfo(GdbMiFieldList info) {
		String id = info.getString("id");
		String targetId = info.getString("target-id");
		String name = info.getString("name");
		String state = info.getString("state");
		String core = info.getString("core");
		Collection<Object> finfo = info.get("frame");
		List<GdbFrameInfo> frames = new ArrayList<>();
		for (Object object : finfo) {
			if (object instanceof GdbMiFieldList) {
				frames.add(GdbFrameInfo.parseInfo((GdbMiFieldList) object));
			}
		}
		return new GdbThreadInfo(id, targetId, name, state, core, frames);
	}

	private final String id;
	private final String targetId;
	private final String name;
	private final String state;
	private final String core;
	private final List<GdbFrameInfo> frames;
	private BigInteger addr;
	private Integer tid;

	/**
	 * Construct GDB thread information
	 * 
	 * @param id the GDB-assigned id
	 * @param targetId the system id
	 * @param name the inferior name
	 * @param state current thread state
	 * @param core the active core
	 * @param frames thread stack
	 */
	GdbThreadInfo(String id, String targetId, String name, String state, String core,
			List<GdbFrameInfo> frames) {
		this.id = id;
		this.targetId = targetId;
		this.name = name;
		this.frames = frames;
		this.state = state;
		this.core = core;
		Matcher mappingMatcher = TARGET_ID_LINE_PATTERN0.matcher(targetId);
		if (mappingMatcher.matches()) {
			try {
				this.addr = new BigInteger(mappingMatcher.group("addr"), 16);
				this.tid = Integer.parseInt(mappingMatcher.group("tid"));
				return;
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Could not parse target id: " + targetId, e);
			}
		}
		mappingMatcher = TARGET_ID_LINE_PATTERN1.matcher(targetId);
		if (mappingMatcher.matches()) {
			try {
				this.tid = Integer.parseInt(mappingMatcher.group("tid"));
			}
			catch (NumberFormatException e) {
				Msg.error(this, "Could not parse target id: " + targetId, e);
			}
		}
	}

	@Override
	public int hashCode() {
		return Objects.hash(getId(), getTargetId());
	}

	@Override
	public String toString() {
		return "<GdbThreadInfo id=" + getId() + ",target-id=" + getTargetId() + ">";
	}

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof GdbThreadInfo))) {
			return false;
		}
		GdbThreadInfo that = (GdbThreadInfo) obj;
		if (this.getId() != that.getId()) {
			return false;
		}
		if (this.getTargetId() != that.getTargetId()) {
			return false;
		}
		return true;
	}

	public String getId() {
		return id;
	}

	public String getTargetId() {
		return targetId;
	}

	public String getInferiorName() {
		return name;
	}

	public String getState() {
		return state;
	}

	public String getCore() {
		return core;
	}

	public List<GdbFrameInfo> getFrames() {
		return frames;
	}

	public BigInteger getAddr() {
		return addr;
	}

	public Integer getTid() {
		return tid;
	}

}
