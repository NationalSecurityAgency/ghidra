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
package ghidra.dbg.sctl.err;

import ghidra.dbg.sctl.protocol.common.reply.SctlErrorReply;

/**
 * An exception to describe errors detected by the SCTL server
 * 
 * On the client side, this exception is thrown whenever an {@code Rerror} message is received.
 * Usually, this results in a future completing exceptionally.
 * 
 * For server implementations using this module, this exception can be thrown within request
 * handlers. This will cause the client handler to generate an {@code Rerror} for the request that
 * was being handled.
 */
public class SctlError extends SctlRuntimeException {

	/**
	 * Server side: Construct an exception to generate {@code Rerror}
	 * 
	 * @param message a human-readable description of the error
	 */
	public SctlError(String message) {
		super(message);
	}

	/**
	 * Client side: Construct an exception for a received {@code Rerror}
	 * 
	 * @param reply the received {@code Rerror}
	 */
	public SctlError(SctlErrorReply reply) {
		super("Server reported error: " + reply.msg);
	}
}
