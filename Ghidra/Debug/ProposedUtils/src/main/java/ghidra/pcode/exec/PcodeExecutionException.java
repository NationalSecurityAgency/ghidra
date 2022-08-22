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
package ghidra.pcode.exec;

/**
 * The base exception for all p-code execution errors
 * 
 * <p>
 * Exceptions caught by the executor that are not of this type are typically caught and wrapped, so
 * that the frame can be recovered. The frame is important for diagnosing the error, because it
 * records what the executor was doing. It essentially serves as the "line number" of the p-code
 * program within the greater Java stack. Additionally, if execution of p-code is to resume, the
 * frame must be recovered, and possibly stepped back one.
 */
public class PcodeExecutionException extends RuntimeException {

	/*package*/ PcodeFrame frame;

	/**
	 * Construct an execution exception
	 * 
	 * <p>
	 * The frame is often omitted at the throw site. The executor should catch the exception, fill
	 * in the frame, and re-throw it.
	 * 
	 * @param message the message
	 * @param frame if known, the frame at the time of the exception
	 * @param cause the exception that caused this one
	 */
	public PcodeExecutionException(String message, PcodeFrame frame, Throwable cause) {
		super(message, cause);
		this.frame = frame;
	}

	public PcodeExecutionException(String message, PcodeFrame frame) {
		this(message, frame, null);
	}

	public PcodeExecutionException(String message, Throwable cause) {
		this(message, null, cause);
	}

	public PcodeExecutionException(String message) {
		this(message, null, null);
	}

	/**
	 * Get the frame at the time of the exception
	 * 
	 * <p>
	 * Note that the frame counter is advanced <em>before</em> execution of the p-code op. Thus, the
	 * counter often points to the op following the one which caused the exception. For a frame to
	 * be present and meaningful, the executor must intervene between the throw and the catch. In
	 * other words, if you're invoking the executor, you should always expect to see a frame. If you
	 * are implementing, e.g., a userop, then it is possible to catch an exception without frame
	 * information populated. You might instead retrieve the frame from the executor, if you have a
	 * handle to it.
	 * 
	 * @return the frame, possibly {@code null}
	 */
	public PcodeFrame getFrame() {
		return frame;
	}
}
