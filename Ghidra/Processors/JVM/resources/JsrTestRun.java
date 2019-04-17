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
//ecj -1.4 JsrTest.java to get jsr and ret in the classfile
class JsrTestRun{

    public static void main(String[] args){
        System.out.println(tryObject("test"));
        return;
    }


    public static String tryObject(Object o){
        String x = null;
        try{
           x = o.toString();
        }
        catch (Exception e){
        }
        finally{
           if (x == null){
               x = "null";
           } 
        }
        return x;
    }

}   
