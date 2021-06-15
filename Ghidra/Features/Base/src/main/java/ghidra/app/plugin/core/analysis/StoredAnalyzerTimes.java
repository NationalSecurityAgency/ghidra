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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.framework.options.*;
import ghidra.program.model.listing.Program;
import ghidra.util.StringUtilities;

/**
 * <code>StoredAnalyzerTimes</code> provides a custom option container for 
 * accumulated analysis times for named tasks.
 */
public class StoredAnalyzerTimes implements CustomOption {

	public static final String OPTIONS_LIST = Program.PROGRAM_INFO + ".Analysis Times";
	public static final String OPTION_NAME = "Times";

	// all times maintained in milliseconds
	private Map<String, Long> taskTimes = new HashMap<>();
	private Long totalTime;
	private String[] names;

	@Override
	public void readState(SaveState saveState) {
		taskTimes.clear();
		for (String taskName : saveState.getNames()) {
			if (CustomOption.CUSTOM_OPTION_CLASS_NAME_KEY.equals(taskName)) {
				continue; // skip this reserved key 
			}
			taskTimes.put(taskName, saveState.getLong(taskName, 0));
		}
		names = null;
		totalTime = null;
	}

	@Override
	public void writeState(SaveState saveState) {
		for (String taskName : taskTimes.keySet()) {
			saveState.putLong(taskName, taskTimes.get(taskName));
		}
	}

	/**
	 * Clear all task entries and times
	 */
	public void clear() {
		taskTimes.clear();
		names = null;
		totalTime = null;
	}

	/**
	 * Determine if any task times exist
	 * @return true if no task times available, else false
	 */
	public boolean isEmpty() {
		return taskTimes.isEmpty();
	}

	/**
	 * Clear time entry corresponding to specified taskName
	 * @param taskName analysis task name
	 */
	public void clear(String taskName) {
		taskTimes.remove(taskName);
		names = null;
		totalTime = null;
	}

	/**
	 * Add the specified time corresponding to the specified analysis taskName
	 * @param taskName analysis task name
	 * @param t time increment in milliseconds
	 */
	public void addTime(String taskName, long t) {
		long cumulativeTime = taskTimes.getOrDefault(taskName, 0L) + t;
		taskTimes.put(taskName, cumulativeTime);
		names = null;
		totalTime = null;
	}

	/**
	 * Get the accumulated time for the specified analysis taskName
	 * @param taskName analysis task name
	 * @return accumulated task time in milliseconds or null if entry not found
	 */
	public Long getTime(String taskName) {
		return taskTimes.get(taskName);
	}

	/**
	 * Get the total accumulated task time for all task entries
	 * in milliseconds
	 * @return total accumuated task time in milliseconds
	 */
	public long getTotalTime() {
		if (totalTime == null) {
			long sum = 0;
			for (long t : taskTimes.values()) {
				sum += t;
			}
			totalTime = sum;
		}
		return totalTime;
	}

	@Override
	public String toString() {
		return formatTimeMS(getTotalTime()) + " seconds";
	}

	/**
	 * Get all task names for which time entries exist
	 * @return array of task names
	 */
	public String[] getTaskNames() {
		if (names == null) {
			names = taskTimes.keySet().toArray(new String[taskTimes.size()]);
			Arrays.sort(names);
		}
		return names;
	}

	@Override
	public int hashCode() {
		return taskTimes.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof StoredAnalyzerTimes)) {
			return false;
		}
		return taskTimes.equals(((StoredAnalyzerTimes) obj).taskTimes);
	}

	@Override
	public StoredAnalyzerTimes clone() {
		StoredAnalyzerTimes newInstance = new StoredAnalyzerTimes();
		newInstance.taskTimes = new HashMap<>(taskTimes);
		return newInstance;
	}

	/**
	 * Get the StoredAnalyzerTimes options data from the specified program
	 * @param program program
	 * @return StoredAnalyzerTimes option data
	 */
	public static StoredAnalyzerTimes getStoredAnalyzerTimes(Program program) {
		Options options = program.getOptions(OPTIONS_LIST);
		StoredAnalyzerTimes times = (StoredAnalyzerTimes) options
			.getCustomOption(StoredAnalyzerTimes.OPTION_NAME, new StoredAnalyzerTimes());
		return times;
	}

	/**
	 * Set the updated StoredAnalyzerTimes option data on the specified program
	 * @param program program
	 * @param times StoredAnalyzerTimes option data
	 */
	public static void setStoredAnalyzerTimes(Program program, StoredAnalyzerTimes times) {
		Options options = program.getOptions(OPTIONS_LIST);
		options.putObject(StoredAnalyzerTimes.OPTION_NAME, times);
	}

	static String formatTimeMS(long timeMS) {
		String str = Long.toUnsignedString(timeMS / 1000L);
		str += ".";
		str += StringUtilities.pad(Long.toUnsignedString(timeMS % 1000L), '0', 3);
		return str;
	}

}
