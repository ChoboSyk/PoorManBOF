import json
import os
import glob
import requests
import re
from bs4 import BeautifulSoup
import shutil

allApis = []
addToCFile = []
allDeclarations = []
dllsToImport = []
allDefinitions = []

runCFile = """#include "run.h"

void run(char* output)
{
#pragma region function-resolution
/// Resolve the address of KERNEL32.DLL via djb2 hash.
    LPVOID kernel32dll = NULL;
    kernel32dll = GetModuleByHash(KERNEL32DLL_HASH1);
    if (NULL == kernel32dll)
    {
        /// Resolve the address of kernel32.dll via djb2 hash.
        kernel32dll = GetModuleByHash(KERNEL32DLL_HASH2);
        if (NULL == kernel32dll)
        {
            /// Resolve the address of Kernel32.dll via djb2 hash.
            kernel32dll = GetModuleByHash(KERNEL32DLL_HASH3);
            if (NULL == kernel32dll) {
                return;
            }
        }
    }

    LOADLIBRARYA LoadLibraryAFunc;
    UINT64 msvcrtdll;
    STRLEN strlenFunc;
    CHAR loadlibrarya_c[] = "LoadLibraryA";
    LoadLibraryAFunc = _GetProcAddress((HANDLE)kernel32dll, loadlibrarya_c);
    CHAR msvcrt_c[] = "msvcrt.dll";
    msvcrtdll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(msvcrt_c);
    CHAR strlen_c[] = "strlen";
    strlenFunc = _GetProcAddress((HANDLE)msvcrtdll, strlen_c);
    
    __REPLACE_ME__
    
    
    //Write Your code here
    //You send text back by using print or println by changing the VALUE_TO_PRINT 
    //to the string you want: "print(&output, strlenFunc, VALUE_TO_PRINT);
    //All Strings must be declared with the CHAR [] varname = ""; format.

    return;
}
"""

runHFile = """#include <windows.h>
#include "function-resolution.h"

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef size_t (*STRLEN)(const char *str);

__REPLACE_ME__

// djb2 hashes for dynamic function resolution.
#define KERNEL32DLL_HASH1   0xa709e74f /// Hash of KERNEL32.DLL
#define KERNEL32DLL_HASH2   0xa96f406f /// Hash of kernel32.dll
#define KERNEL32DLL_HASH3   0x8b03944f /// Hash of Kernel32.dll

void println(char** output, STRLEN strlenFunc, CHAR text[]) {
	
	for (int i = 0; i < strlenFunc(text); i++) {
		**output = text[i];
		*output = *output + 1;
	}
	**output = 0x0a;
	*output = *output + 1;
}

void print(char** output, STRLEN strlenFunc, CHAR text[]) {
	for (int i = 0; i < strlenFunc(text); i++) {
		**output = text[i];
		*output = *output + 1;
	}
}

"""

def findAPI(apiName):
    for api in allApis:
        if api["name"].lower() == apiName.lower():
            return api
    return "NotFound"

def buildTypeDef(apiName,returnType,arguments):
    typdef = "typedef " + str(returnType) + "(WINAPI* " + apiName.upper() + ")("
    for arg in arguments:
        typdef = typdef + str(arg["type"]) + ","
    if len(arguments) > 0:
        typdef = typdef[:-1]
    typdef = typdef + ");"
    return typdef

def buildFuncDelcaration(apiName):
    return apiName.upper() + " " + apiName + "Func;"

def buildNameCharArray(apiName):
    return "CHAR " + apiName.lower()  + "_c[] = \"" + apiName + "\";"

def buildGetProcAddr(apiName, dllHostingApi):
    return apiName + "Func = _GetProcAddress((HANDLE)" + dllHostingApi.replace(".", "").lower() + "," + apiName.lower() + "_c);"

def generateWinAPIHeader(apis):
        winApiHeaderFile = open("C:\\Users\\Samue\\Documents\\tools\SleepyCrypt\\winapis2.h","w")
        winApiHeaderFile.write("#include <windows.h>\n")
        for api in apis:
            apiName = api["name"]
            returnType = api["return_type"]
            arguments = api["arguments"]
            dll = api["dll"]
            dll = dll.split(" ")[0]
            if "kernel32" not in dll.lower() and "msvcrt" not in dll.lower():
                dllsToImport.append(dll)
            typedef = buildTypeDef(apiName, returnType, arguments)
            allDefinitions.append(typedef)
            print(typedef)
            allDeclarations.append(buildFuncDelcaration(apiName))
            addToCFile.append(buildNameCharArray(apiName))
            addToCFile.append(buildGetProcAddr(apiName, dll))

def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

def parseMSDNPage(apiName, apiToGenerate):
    apiName = apiName.replace("--", "-")
    URL = "https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/" + apiName + "?view=msvc-170"
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, "html.parser")
    results = soup.find_all("code", {"class": "lang-C"})
    file = open("FormatToAddMissingWinAPI.txt", "a")
    methodName = ""
    if len(results) > 0:
        results = comment_remover(results[0].string)
        results = results.split(";")
        results.pop()
        for index, result in enumerate(results):
            results[index] = result.replace("\n","")
            if "C++" in results[index] or "#define" in results[index]:
                results[index] = None

        results = [i for i in results if i]
        for index, result in enumerate(results):
            allFunctions = result.split(" ")
            for function in allFunctions:
                if "(" in function:
                    methodName = function.replace("(", "")

                    addVoid = ""
                    if "*" in methodName:
                        addVoid = "*"
                        methodName = methodName.replace("*", "")
                    if methodName and result and methodName == apiToGenerate:
                        #print(methodName)
                        if "[" in result:
                         result = result[:result.find("[")] + "," + result[result.find("]")+1:]
                        vars = result.split("(")[1].split(")")[0].split(",")
                        for index, var in enumerate(vars):
                            vars[index] = var.strip()
                        returnType = result.split(methodName)[0]
                        definition = "typedef " + returnType +"(*" + methodName.upper() + ")("
                        for var in vars:
                            definition = definition + var + ","
                        definition = definition[:-1]
                        definition = definition + ");"
                        definition = definition
                        declaration = methodName.upper() + " " + methodName +"Func;"
                        badCharsDef = ["{", "}", "<", ">", "&&"]
                        badCharsDecla = [".", ",", ")", "("]
                        badCharCountDefinition = [e for e in badCharsDef if e in definition]
                        badCharCountDecla= [e for e in badCharsDecla if e in declaration]
                        if len(badCharCountDefinition) == 0 and len(badCharCountDecla) == 0:
                            print(definition)
                            allDefinitions.append(definition)
                            allDeclarations.append(declaration)
                            addToCFile.append(buildNameCharArray(methodName))
                            addToCFile.append(buildGetProcAddr(methodName, "msvcrtdll"))
                            return

def findAPIOnline(apiToGenerate):
    path = "CRunTimeFunctions.txt"
    file = open(path, "r")
    lines = file.readlines()
    for index, line in enumerate(lines):
        splitFunc =  line.replace(" ", "").split(",")
        for index, func in  enumerate(splitFunc):
            splitFunc[index] = func.replace("\n","")
        function = line.strip().replace(",", "").replace(" ", "-")
        if function[0] == "_":
            function = function[1:]
        function = function.replace("_", "-")
        function = function.replace("--", "-")
        function = function.replace("(CRT)", "crt")
        if apiToGenerate in splitFunc:
            parseMSDNPage(function, apiToGenerate)

def copyTemplates(dirToCreate):
    if os.path.isdir(dirToCreate):
        shutil.rmtree(dirToCreate)

    source_folder = "./Templates/"
    destination_folder = "./" + dirToCreate
    os.mkdir(destination_folder)

    for file_name in os.listdir(source_folder):
        source = source_folder + file_name
        destination = destination_folder + "/" + file_name
        if os.path.isfile(source):
            shutil.copy(source, destination)


if __name__ == '__main__':
    projectNameAkaDirName = "testProject"
    copyTemplates(projectNameAkaDirName)

    apisNotFoundInJson = []

    path = 'api_by_category'
    for filename in glob.glob(os.path.join(path, '*.json')):
        with open(os.path.join(os.getcwd(), filename), 'r') as f:  # open in readonly mode
            allApis = allApis + json.load(f)

    #apisRequested = ["OpenProcess", "GetCurrentProcess", "OpenProcessToken", "LookupPrivilegeValueA", "AdjustTokenPrivileges", "DuplicateToken", "SetThreadToken"]
    apisRequested = ["Sleep"]
    result = []
    for api in apisRequested:
        apiName = api
        openProcessApi = findAPI(apiName)

        #Pretty much checks if the api provided is an A or W version and in the list theyre all in absolute versions
        if openProcessApi == "NotFound" and (apiName[-1] == "A" or apiName[-1] == "W"):
            wOrA = apiName[-1]
            if wOrA == "W":
                print("Warning: You have requested: " + apiName +".Its a W version of an API. The A version will be provided instead. If you really want the W version make the changes manually.")
            apiName = apiName[:-1]
            openProcessApi = findAPI(apiName)
            openProcessApi["name"] = apiName + "A"
            # If not found in the json well look after online
        if openProcessApi == "NotFound":
            apisNotFoundInJson.append(apiName)
        else:
            result.append(openProcessApi)

    #Generate headers only for the requested APIS by the user. Save us some time
    print("-----------------------Add the values to the H File----------------------")
    generateWinAPIHeader(result)


    for api in apisNotFoundInJson:
        findAPIOnline(api)
    dllHString = ""
    dllsToImport = list(dict.fromkeys(dllsToImport))
    for dll in dllsToImport:
        dllHString = dllHString + dll +", "
    if len(dllsToImport) > 0:
        dllHString = "UINT64 " + dllHString[:-2].replace(".","").lower() + ";"

    print("-----------------------Add the values to the C File----------------------")
    replaceInCFile = ""
    print(dllHString)
    replaceInCFile = replaceInCFile + dllHString + "\n"
    for decla in allDeclarations:
        print(decla)
        replaceInCFile = replaceInCFile + "\t" +decla + "\n"
    for dll in dllsToImport:
        chararrayName = dll[:dll.find(".")]+"_c"
        print("CHAR " + chararrayName + "[] = \"" + dll.lower() +"\";")
        print(dll.lower().replace(".","") + " = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(" +chararrayName +");")
        replaceInCFile = replaceInCFile + "\tCHAR " + chararrayName + "[] = \"" + dll.lower() +"\";" + "\n"
        replaceInCFile = replaceInCFile + "\t" +dll.lower().replace(".","") + " = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(" +chararrayName +");" + "\n"
    for header in addToCFile:
        #print(header)
        replaceInCFile = replaceInCFile + "\t" +header + "\n"

    #Write the run.c file
    runCFile = runCFile.replace("__REPLACE_ME__", replaceInCFile)
    cfile = open("./"+projectNameAkaDirName + "/run.c", "w")
    cfile.write(runCFile)
    cfile.close()

    #Write the run.h file
    concatenatedDefinitions = ""
    for definition in allDefinitions:
        concatenatedDefinitions = concatenatedDefinitions + "\n" + definition
    runHFile = runHFile.replace("__REPLACE_ME__", concatenatedDefinitions)
    cfile = open("./" + projectNameAkaDirName + "/run.h", "w")
    cfile.write(runHFile)
    cfile.close()



