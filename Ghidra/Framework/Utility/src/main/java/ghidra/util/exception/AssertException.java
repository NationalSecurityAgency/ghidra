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
package ghidra.util.exception;

/**
 * <code>AssertException</code> is used in situations that the programmer believes can't happen.
 * If it does, then there is a programming error of some kind.
 */
public class AssertException extends RuntimeException {
    
    /**
     * Create a new AssertException with no message.
     */
    public AssertException() {
        super("Unexpected Error");
    }

    /**
     * Create a new AssertException with the given message.
     *
     * @param msg the exception message.
     */
    public AssertException(String msg) {
        super(msg);
    }
    
    /**
     * Create a new AssertException using another exception (Throwable) has occurred.
     * The message for this exception will be derived from the Throwable.
     * @param t the Throwable which caused this exception to be generated.
     */
    public AssertException(Throwable t) {
    	super("Unexpected Error: " + (t.getMessage() == null ? t.toString() : t.getMessage()), t);
    }
    
    /**
     * Create a new AssertException with the given message.
     *
     * @param message the exception message.
     * @param throwable the Throwable which caused this exception to be generated.
     */
    public AssertException( String message, Throwable throwable ) {
    	super( message, throwable );
    }
}
