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
package ghidra.app.util.recognizer;

import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL Recognizer CLASSES MUST END IN "Recognizer".  If not,
 * the ClassSearcher will not find them.
 *
 */
public interface Recognizer extends ExtensionPoint {

    /**
     * How many bytes (maximum) does this recognizer need to recognize its
     * format?
     * 
     * @return the maximum number of bytes needed to send to this recognizer in
     *         the recognize(...) method
     */
    public int numberOfBytesRequired();

    /**
     * Ask the recognizer to recognize some bytes. Return a description String
     * if recognized; otherwise, null. DO NOT MUNGE THE BYTES. Right now for
     * efficiency's sake the array of bytes is just passed to each recognizer in
     * turn. Abuse this and we will need to create copies, and everyone loses.
     * 
     * @param bytes the bytes to recognize
     * @return a String description of the recognition, or null if it is not
     *         recognized
     */
    public String recognize(byte[] bytes);

    /**
     * Return the recognizer priority; for instance, a GZIP/TAR recognizer
     * should have higher priority than just the GZIP recognizer (because the
     * GZIP/TAR will unzip part of the payload and then test against the TAR
     * recognizer...so every GZIP/TAR match will also match GZIP). Note that
     * higher is more specific, which is opposite the convention used with the
     * Loader hierarchy.
     * 
     * @return the recognizer priority
     */
    public int getPriority();
}
