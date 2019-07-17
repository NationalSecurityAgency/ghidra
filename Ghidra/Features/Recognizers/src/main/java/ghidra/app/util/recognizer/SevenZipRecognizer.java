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

public class SevenZipRecognizer implements Recognizer {
    public String recognize(byte[] bytes) {
        if (bytes.length >= numberOfBytesRequired()) {
            if (bytes[0] == (byte) 0x37 &&
                bytes[1] == (byte) 0x7a &&
                bytes[2] == (byte) 0xbc &&
                bytes[3] == (byte) 0xaf &&
                bytes[4] == (byte) 0x27 &&
                bytes[5] == (byte) 0x1c) {
                return "File appears to be a 7-ZIP compressed file";
            }
        }
        return null;
    }

    public int getPriority() {
        return 100;
    }

    public int numberOfBytesRequired() {
        return 6;
    }
}
