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
package agent.gdb.manager.evt;

import java.util.Objects;

import agent.gdb.manager.GdbLibraryId;
import agent.gdb.manager.parsing.GdbParsingUtils;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;

/**
 * A base class for GDB events regarding loaded libraries
 */
public abstract class AbstractGdbLibraryEvent extends AbstractGdbEventWithFields {
	private final GdbLibraryId lid;
	private final String targetName;
	private final Integer iid;

	private static class LibId implements GdbLibraryId {
		private final String id;

		public LibId(String id) {
			this.id = id;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof LibId)) {
				return false;
			}
			LibId that = (LibId) obj;
			return Objects.equals(this.id, that.id);
		}

		@Override
		public int hashCode() {
			return id.hashCode();
		}
	}

	/**
	 * Construct a new event, parsing the tail for information
	 * 
	 * The library's ID and target name must be specified by GDB. The applicable inferiors
	 * (actually, thread groups) may also be specified. If not, the manager assumes all inferiors.
	 * 
	 * @param tail the text following the event type in the GDB/MI event record
	 * @throws GdbParseError if the tail cannot be parsed
	 */
	public AbstractGdbLibraryEvent(CharSequence tail) throws GdbParseError {
		super(tail);
		this.lid = new LibId(getInfo().getString("id"));
		this.targetName = getInfo().getString("target-name");
		String gid = getInfo().getString("thread-group");
		if (gid == null) {
			this.iid = null;
		}
		else {
			this.iid = GdbParsingUtils.parseInferiorId(gid);
		}
	}

	/**
	 * Get the library ID
	 * 
	 * @return the ID
	 */
	public GdbLibraryId getLibraryId() {
		return lid;
	}

	/**
	 * Get the target's name for the library
	 * 
	 * @return the name
	 */
	public String getTargetName() {
		return targetName;
	}

	/**
	 * Get the applicable
	 * 
	 * @return
	 */
	public Integer getInferiorId() {
		return iid;
	}
}
