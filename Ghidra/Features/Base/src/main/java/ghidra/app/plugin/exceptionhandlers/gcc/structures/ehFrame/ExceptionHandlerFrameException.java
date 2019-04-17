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
package ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame;

/** Generic Exception class for classes contained in the ehFrame package */
public class ExceptionHandlerFrameException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructs a new ExceptionHandlerFrameException with the specified detail message and
	 * cause.
	 */
	public ExceptionHandlerFrameException() {
		super();
	}

	/**
	 * Constructs a new ExceptionHandlerFrameException with the specified detail message and
	 * cause.
	 *
	 * @param message the detail message.
	 * @param cause the cause of this exception being thrown.
	 */
	public ExceptionHandlerFrameException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a new ExceptionHandlerFrameException with the specified detail message.
	 *
	 * @param message the detail message.
	 */
	public ExceptionHandlerFrameException(String message) {
		super(message);
	}

	/**
	 * Constructs a new ExceptionHandlerFrameException with the specified cause.
	 *
	 * @param cause the cause of this exception being thrown.
	 */
	public ExceptionHandlerFrameException(Throwable cause) {
		super(cause);
	}
}
