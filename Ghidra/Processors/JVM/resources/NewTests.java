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
class NewTests{
    private Integer intValue;
    private String stringValue;

    public Object integerTest1(){
        return new Integer(1234); 
    }

    public NewTests(Integer a, String b){
        intValue = a;
        stringValue = b;
    }

    public NewTests callsConstructor(Integer a, String b){
        return new NewTests(a,b);
    }

    public NewTests callsConstructor2(int x, String b){
        return new NewTests(new Integer(2*x), b+b);
    } 

    public String callsConstructor3(int x, String b){
        return getString(new NewTests(new Integer(2*x), b+b));
    } 

    public String getString(NewTests test){
        return test.toString();
    }

}
