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
package ghidra.app.util.recognizer;

public class DebRecognizer implements Recognizer {
    public String recognize(byte[] bytes) {
        if (bytes.length >= numberOfBytesRequired()) {
            if (bytes[0] == (byte) 0x21 &&
                bytes[1] == (byte) 0x0a &&
                bytes[2] == (byte) 0x64 &&
                bytes[3] == (byte) 0x65 &&
                bytes[4] == (byte) 0x62 &&
                bytes[5] == (byte) 0x69 &&
                bytes[6] == (byte) 0x61 &&
                bytes[7] == (byte) 0x6e) {
                return "File appears to be a Debian package file";
            }
        }
        return null;
    }

    public int getPriority() {
        return 100;
    }

    public int numberOfBytesRequired() {
        return 8;
    }
}
