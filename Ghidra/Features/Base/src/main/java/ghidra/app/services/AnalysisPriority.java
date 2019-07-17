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
package ghidra.app.services;

/**
 * Class to specify priority within the Automated Analysis pipeline.
 *
 */
public class AnalysisPriority {
	/**
	 * These priorities are generally the order in which basic components are
	 *   laid down in the program.  There are basic analyzers that get kicked off at a
	 *   particular priority, like the ReferenceAnalyzer runs at the REFERENCE_ANALYZER
	 *   priority.  So you can schedule your analyzer around one of those basic analyzers.
	 *   If an analyzer produces references that the reference analyzer should pick
	 *   up, set a higher priority than the reference analyzer.  If the analyzer depends on data having
	 *   been created because of the reference analyzer, schedule with a lower priority than
	 *   REFERENCE_ANALYZER.
	 *   
	 * Analyzers that are higher priority happen earlier, and are generally more sure about
	 *   the information they lay down.
	 * 
	 * Analyzers that happen later in analysis pipeline because of a low priority depend on
	 *   prior analysis.  For example, you can't analyze functions before you have laid down code
	 *   and found call references to those functions.
	 * 
	 * Analyzers that are of the lowest priority, tend to be more speculative in the information
	 *   they lay down.  For example taking a scalar value and using it as a pointer without
	 *   any other corroborating information that it is a pointer is speculative and should
	 *   happen with a low priority.
	 * 
	 */
	

	/**
	 * Defines a full format analysis as the first priority for automatic analysis.
	 * These are the first analyzers that will run after import.
	 * Possibly there is a need to move blocks around, or create headers.
	 * Analyzers that will look binary as a full file format analysis
	 * should run with this priority.
	 * 
	 * NOTE: there may be analyzers that run before this that need to fix issues like Non-Returning
	 * functions.  Be very careful running an analyzer with a higher priority.
	 */
	public final static AnalysisPriority FORMAT_ANALYSIS = AnalysisPriority.getInitial("FORMAT");

	/**
	 * Defines block analysis as the second priority for automatic analysis.
	 * Initial markup of raw bytes should occur at or after this priority (images, etc).
	 * The initial disassembly of EntryPoints will occur at this priority.
	 */
	public final static AnalysisPriority BLOCK_ANALYSIS = FORMAT_ANALYSIS.getNext("BLOCK");

	/**
	 * Defines disassembly as the third priority for automatic analysis.
	 * Disassembly of code found through good solid flow will occur at this priority.
	 * More heuristic code recovery will occur later.
	 */
	public final static AnalysisPriority DISASSEMBLY = BLOCK_ANALYSIS.getNext("DISASSEMBLY");

	/**
	 * Defines code analysis as the fourth priority for automatic analysis.
	 * If your analyzer is looking at RAW CODE, you should general go at or after this
	 * priority.  Usually this is used in conjunction with analyzers that process new
	 * instructions <code>AnalyzerType.INSTRUCTIONS</code>.  It is also useful for
	 * those analyzers that depend on code, but want to analyze flow, such as non-returning
	 * functions, that should happen before functions are widely laid down.  If
	 * bad flow is not fixed at an early priority, switch stmt recovery, function
	 * boundaries, etc... may need to be redone and bad stuff cleaned up.
	 */
	public final static AnalysisPriority CODE_ANALYSIS = DISASSEMBLY.getNext("CODE");

	/**
	 * Defines function analysis as the fifth priority for automatic analysis.
	 * After this priority, basic functions and their instructions should be recovered.
	 * More functions could be recovered in further analysis, but if your analysis
	 * depends on basic function creation, you should go after this priority.
	 */
	public final static AnalysisPriority FUNCTION_ANALYSIS = CODE_ANALYSIS.getNext("FUNCTION");

	/**
	 * Defines reference analysis as the sixth priority for automatic analysis.
	 * After this priority, basic reference recovery should have taken place.
	 * More references could be recovered later.
	 */
	public final static AnalysisPriority REFERENCE_ANALYSIS =
		FUNCTION_ANALYSIS.getNext("REFERENCE");

	/**
	 * Defines data analysis as the seventh priority for automatic analysis.
	 * After this priority, data creation (strings, pointers) should have settled down.
	 * More data can be recovered with further analysis.
	 */
	public final static AnalysisPriority DATA_ANALYSIS = REFERENCE_ANALYSIS.getNext("DATA");

	/**
	 * Defines Function identification analysis as the eighth priority for automatic analysis.
	 * After this priority, full function (name/class) evaluation should have taken place.
	 */
	public final static AnalysisPriority FUNCTION_ID_ANALYSIS =
		DATA_ANALYSIS.getNext("FUNCTION ID");

	/**
	 * Defines data type propogation as the ninth priority for automatic analysis.
	 * Data type propogation analysis should hapen as late as possible so that all basic code
	 * recovery, reference analysis, etc... has taken place.
	 */
	public final static AnalysisPriority DATA_TYPE_PROPOGATION =
		FUNCTION_ID_ANALYSIS.getNext("DATA TYPE PROPOGATION");

	public static final AnalysisPriority LOW_PRIORITY = new AnalysisPriority("LOW", 10000);

	// This used to be 0, but it allowed HIGHEST_PRIORITY tasks to yield to lower tasks (See yield method), which seems wrong in its own right
	public static final AnalysisPriority HIGHEST_PRIORITY = new AnalysisPriority("HIGH", 1);

	private int priority;

	private String name;

	public AnalysisPriority(int priority) {
		this(null, priority);
	}

	/**
	 * Construct a new priority object.
	 * @param priority priority to use
	 */
	public AnalysisPriority(String name, int priority) {
		this.name = name;
		this.priority = priority;
	}

	/**
	 * Return the priority specified for this analysis priority.
	 */
	public int priority() {
		return priority;
	}

	/**
	 * Get a priority that is a little higher than this one.
	 * 
	 * @return a higher priority
	 */
	public AnalysisPriority before() {
		return new AnalysisPriority(name + "-", priority - 1);
	}

	/**
	 * Get a piority that is a little lower than this one.
	 * 
	 * @return a lower priority
	 */
	public AnalysisPriority after() {
		return new AnalysisPriority(name + "+", priority + 1);
	}

	/**
	 * Return first gross priority.
	 * @return first gross priority
	 */
	public static AnalysisPriority getInitial(String name) {
		return new AnalysisPriority(name, 100);
	}

	/**
	 * Get the next gross priority.
	 * @return return next gross priority
	 */
	public AnalysisPriority getNext(String nextName) {
		return new AnalysisPriority(nextName, priority + 100);
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		if (name != null) {
			buf.append("[").append(name).append("]  ");
		}
		buf.append(priority);
		return buf.toString();
	}
}
