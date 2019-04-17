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
package ghidra.app.util.opinion;

/**
 * A class to represent an error when processing an opinion.
 */
public class OpinionException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
     * Constructs a new opinion exception with the specified detail message.
     * @param msg the detail message
     */
    public OpinionException(String msg) {
        super(msg);
    }
    /**
     * Constructs a new exception with the specified cause
     * @param cause the cause of the exception
     */
    public OpinionException(Exception cause) {
        super(cause);
    }
}
