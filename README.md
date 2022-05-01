# connect-csharp
The CSharp Agent for Connect.

### Important Notes
- The agent takes to arguments: The Server URI and The check_in job ID.
- The agent requires Newtonsoft.Json from the NUGet package manager to be installed.
- Once built, merge system.net and newtonsoft.json DLL's to the exectuable with ILMerge using:

```
ILMerge.exe "C:\Users\Username\Documents\ConnectAgent\bin\Release\ConnectAgent.exe" /out:"C:\Users\Skyler Knecht\Desktop\AgentMerged.exe" "C:\Users\Username\Documents\ConnectAgent\packages\Newtonsoft.Json.13.0.1\lib\net45\Newtonsoft.Json.dll" "C:\Program Files\Reference Assemblies\Microsoft\Framework\v3.5\System.Net.dll"
```
